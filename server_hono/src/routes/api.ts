import { Hono, Context } from "hono";
import { z } from "zod";
import {generateUUID, ensureRSAKeys, random_bytes, getClientIP, kvLock} from "../tool/tool";
import { CONFIG } from "../config";
import {
    rsa_check_pubkey, base91_decode_to_bytes, base91_encode_from_bytes, rsa2048_decrypt_to_bytes, rsa2048_encrypt_from_bytes, aes256gcm_decrypt_to_str, code_v1_pre_parse,
    code_v1_verify_parse, blake3_digest_from_str, aes256gcm_encrypt_from_str,
    hkdf_sha256_derive_from_bytes, base85_encode_from_bytes, xchacha20poly1305_encrypt_from_str,
    base85_decode_to_bytes, xchacha20poly1305_decrypt_to_str
} from "../tool/pkg/";
import {Product} from "../tool/product";
import {log} from "../tool/log";

const TAG = "AUTH_API";

const Logd = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    const path = c.req.path;
    const method = c.req.method;
    log.d(TAG, `[${method} ${path}][${ip}] ${msg}`);
};

const Logi = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    const path = c.req.path;
    const method = c.req.method;
    log.i(TAG, `[${method} ${path}][${ip}] ${msg}`);
};
const Logw = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    const path = c.req.path;
    const method = c.req.method;
    log.w(TAG, `[${method} ${path}][${ip}] ${msg}`);
};
const Loge = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    const path = c.req.path;
    const method = c.req.method;
    log.e(TAG, `[${method} ${path}][${ip}] ${msg}`);
};


const api = new Hono<{ Bindings: CloudflareBindings }>();


function getKV(c: Context<{ Bindings: CloudflareBindings }>): KVNamespace {
    return c.env.AUTH_KV;
}

function Ok(c: Context, data?: any, message = 'ok'): Response {
    return c.json({ success: true, code: 200, message, data });
}
function Err(c: Context, message = 'error', code = 400): Response {
    return c.json({ success: false, code, message});
}

export async function parseJson<T extends z.ZodTypeAny>(
    c: Context,
    schema: T
): Promise<z.infer<T> | null> {
    try {
        const body = await c.req.json();
        const result = schema.safeParse(body);
        if (!result.success) {
            return null;
        }
        return result.data;
    } catch {
        return null;
    }
}

// ═══════════════════════════════════════════════════════════
//                          中间件
// ═══════════════════════════════════════════════════════════
/// ip限速不在该层实现

/** 全局错误处理 + RSA 密钥初始化 */
api.use("*", async (c, next) => {
    try {
        await ensureRSAKeys(getKV(c));
        const service = c.req.header(CONFIG.SERVICE_HEADER_NAME);
        if (!service || service !== CONFIG.SERVICE_HEADER_VALUE) {
            Logw(c, `服务头不匹配`);
            return c.text("Not Found", 404);
            // return Err(c, "Not Found");
        }
        await next();
    } catch (e) {
        Loge(c, `严重服务器错误: ${e}`);
        return Err(c,"严重服务器错误");
    }
});

// ═══════════════════════════════════════════════════════════
//                        API 路由
// ═══════════════════════════════════════════════════════════gr

api.get("/health", async (c) => {
    try {
        const kv = c.env.AUTH_KV;
        const db = c.env.AUTH_DB;
        const qu = c.env.LOG_QUEUE;
        const rsa_pri_key = await kv.get("rsa_pri_key", "arrayBuffer");
        const rsa_pub_key = await kv.get("rsa_pub_key", "arrayBuffer");
        const all_name_key = await kv.get("P:A");

        if (!rsa_pri_key || !rsa_pub_key || !all_name_key) {
            return Err(c, "服务器错误");
        }
        const sql = 'SELECT id, level, message, tag, created_at FROM logs ORDER BY created_at DESC, id DESC LIMIT ?';
        const { results } = await db.prepare(sql).bind(1).all();
        return  Ok(c,"ok！")
    } catch (e) {
        try {
            log.e(TAG, e as Error);
        } catch (ee) {
            console.error(`服务器严重错误: ${e}\n${ee}`)
        }
        return  Err(c, "服务器错误")
    }
});


api.post("/pub/key/exc1", async (c) => {
    const kv = getKV(c);
    const KeyExc1Body = z.object({
        data: z.string().min(1),
    });

    const body = await parseJson(c, KeyExc1Body);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }

    const client_pub_key = base91_decode_to_bytes(body.data);
    if (!client_pub_key) {
        Logw(c, "Base91编码错误");
        return Err(c,"编码错误");
    }

    if (!rsa_check_pubkey(client_pub_key)) {
        Logw(c, "客户端公钥验证失败");
        return Err(c,"请求参数错误");
    }

    const serverPubKey = await kv.get("rsa_pub_key","arrayBuffer");
    if (!serverPubKey) {
        Loge(c, "服务器公钥不存在");
        return Err(c,"服务器错误");
    }

    const clientIp = getClientIP(c);
    const clientUuid = generateUUID();

    await kv.put(`S:${clientUuid}:${clientIp}`, client_pub_key, {
        expirationTtl: CONFIG.CLIENT_KEY_TTL
    });

    return Ok(c, {
        client_uuid: clientUuid,
        data: base91_encode_from_bytes(new Uint8Array(serverPubKey))
    });
});

api.post("/pub/key/exc2", async (c) => {

    const kv = getKV(c);
    const KeyExc2Body = z.object({
        client_uuid: z.string().min(1),
        data: z.string().min(1), // 服务器公钥加密后的 base91 编码数据
    });
    const body = await parseJson(c, KeyExc2Body);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }

    const clientIp = getClientIP(c);
    const client_pub_key_buffer = await kv.get(`S:${body.client_uuid}:${clientIp}`, "arrayBuffer");
    if (!client_pub_key_buffer) {
        Logw(c, `客户端UUID不存在或已过期: ${body.client_uuid}`);
        return Err(c, "client_uuid不存在或已过期");
    }
    const client_pub_key = new Uint8Array(client_pub_key_buffer);

    const encrypted_data = base91_decode_to_bytes(body.data);
    if (!encrypted_data) {
        Logw(c, "Base91编码错误");
        return Err(c, "编码错误");
    }

    const serverPrivKey = await kv.get("rsa_pri_key", "arrayBuffer");
    if (!serverPrivKey) {
        Loge(c, "服务器私钥不存在");
        return Err(c, "服务器错误");
    }

    const session_key_16_1 = rsa2048_decrypt_to_bytes(new Uint8Array(serverPrivKey), encrypted_data);
    if (!session_key_16_1) {
        Logw(c, "RSA解密失败");
        return Err(c, "解密失败");
    }
    if (session_key_16_1.length !== 16) {
        Logw(c, `session_key长度错误: ${session_key_16_1.length}`);
        return Err(c, "session_key长度错误");
    }

    const session_key_16_2 = random_bytes(16);
    if (!session_key_16_2) {
        Loge(c, "生成随机字节失败");
        return Err(c, "服务器错误");
    }

    let session_key = hkdf_sha256_derive_from_bytes(session_key_16_1,session_key_16_2,32);
    if (!session_key) {
        Loge(c, "HKDF密钥派生失败");
        return Err(c, "服务器错误");
    }

    await kv.put(`S:K:${body.client_uuid}:${clientIp}`, session_key, {
        expirationTtl: CONFIG.CLIENT_KEY_TTL
    });

    const encrypted_session_key = rsa2048_encrypt_from_bytes(client_pub_key,session_key);
    if (!encrypted_session_key) {
        Loge(c, "RSA加密会话密钥失败");
        return Err(c, "服务器错误");
    }

    return Ok(c, {
        data: base91_encode_from_bytes(encrypted_session_key)
    });
});



api.post("/auth/reg/code/v1", async (c) => {

    const kv = getKV(c);
    const AuthRegCodeV1Body = z.object({
        client_uuid: z.string(),
        data_1: z.string(),     // aes256gcm加密的时间戳
        data_2: z.string(),     // ...激活码
        data_3: z.string(),     // ...productId
        data_4: z.string()      // ...binding
    });
    const body = await parseJson(c,AuthRegCodeV1Body);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }


    const clientIp = getClientIP(c);
    const session_key = await kv.get(`S:K:${body.client_uuid}:${clientIp}`, "arrayBuffer")
    if (!session_key) {
        Logw(c, `会话无效, UUID: ${body.client_uuid}`);
        return Err(c,"会话无效");
    }

    const decrypt= (data: string) => {
        const data_decoded = base91_decode_to_bytes(data);
        if (!data_decoded) {return null}
        const data_decrypted = aes256gcm_decrypt_to_str(new Uint8Array(session_key), data_decoded);
        if (!data_decrypted) {return null}
        return data_decrypted;
    }

    const [clientTsSec,code, productId, binding] = await Promise.all([
        decrypt(body.data_1),
        decrypt(body.data_2),
        decrypt(body.data_3),
        decrypt(body.data_4),
    ]);
    if (!clientTsSec || !code || !productId || !binding) {
        Logw(c, "数据解密失败");
        return Err(c, "数据错误")
    }


    const nowSec = Math.floor(Date.now() / 1000);
    const clientSec = Number(clientTsSec);
    if (!Number.isFinite(clientSec)) {
        Logw(c, `时间戳非法: ${clientTsSec}`);
        return Err(c, "时间戳非法");
    }
    const diff = Math.abs(nowSec - clientSec);
    if (diff > 30) {
        Logw(c, `请求已过期, 时间差: ${diff}秒`);
        return Err(c, "请求已过期");
    }

    const clientProductId = Number(productId);
    if (!Number.isFinite(clientProductId)) {
        Logw(c, `产品ID非法: ${productId}`);
        return Err(c, "产品id非法");
    }

    if (!await Product.existsId(kv,clientProductId)) {
        Logw(c, `产品不存在, ID: ${clientProductId}`);
        return Err(c,"不存在的产品");
    }

    const [ok,productKey] = await Product.getKey(kv, clientProductId);
    if (!ok || !productKey) {
        Loge(c, `获取产品密钥失败, ID: ${clientProductId}`);
        return Err(c,"产品错误");
    }

    const code_parse_pre = code_v1_pre_parse(code);
    if (!code_parse_pre) {
        Logw(c, "激活码预解析失败");
        return Err(c,"非法激活码");
    }

    const code_parse = code_v1_verify_parse(new Uint8Array(productKey),code,clientProductId, null);
    if (!code_parse) {
        Logw(c, "激活码验证失败");
        return Err(c,"激活码无效或已过期");
    }



    const code_used_key = `C:U:${blake3_digest_from_str(code)}`
    if (! await kvLock.waitAndAcquire(kv,code_used_key)) {
        Logw(c, "获取激活码锁失败");
        return Err(c,"请求频繁");
    }

    const code_used_json = await kv.get(code_used_key,"json") as { num?: number };
    const code_used = code_used_json?.num ?? 0;


    if (code_used >= code_parse.max_uses) {
        await kvLock.release(kv, code_used_key);
        Logw(c, `激活码已达使用上限: ${code_used}/${code_parse.max_uses}`);
        return Err(c,"该激活码已达使用上限")
    }

    await kv.put(code_used_key, JSON.stringify({num: code_used + 1}));
    await kvLock.release(kv, code_used_key);

    const tag_obj = {
        activation_time_point_sec: nowSec,
        use_max_duration: code_parse.use_max_duration,
        binding: blake3_digest_from_str(binding),
        code_hash: blake3_digest_from_str(code),
        product_id: clientProductId
    };
    const tag_json = JSON.stringify(tag_obj)
    const tag_sig = xchacha20poly1305_encrypt_from_str(productKey, tag_json)
    if (!tag_sig) {
        Loge(c, "License生成失败");
        return Err(c,"license生成错误");
    }

    const json = JSON.stringify({
        activation_time_point_sec: tag_obj.activation_time_point_sec,
        use_max_duration: tag_obj.use_max_duration,
        binding: tag_obj.binding,
        code_hash: tag_obj.code_hash,
        product_id: tag_obj.product_id,
        tag_sig: base85_encode_from_bytes(tag_sig)
    });
    const json_encrypted = aes256gcm_encrypt_from_str(new Uint8Array(session_key), json);
    if (!json_encrypted) {
        Loge(c, "响应数据加密失败");
        return  Err(c,"服务器错误");
    }

    Logi(c, `激活码注册成功, 产品ID: ${clientProductId}, 有效期: ${code_parse.use_max_duration}秒,激活码已使用次数: ${code_used + 1}/${code_parse.max_uses}`);

    return Ok(c,base91_encode_from_bytes(json_encrypted));
});

api.post("/auth/again/reg/code", async (c) => {

    const kv = getKV(c);
    const AuthAgainRegCodeBody = z.object({
        client_uuid: z.string().min(1),
        data_1: z.string().min(1),     // aes256gcm加密的时间戳
        data_2: z.string().min(1),     // aes256gcm加密的tag_sig(base85编码)
        data_3: z.string().min(1),      // aes256gcm加密的binding
        data_4: z.string().min(1),      // ...产品id
    });
    const body = await parseJson(c, AuthAgainRegCodeBody);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }


    const clientIp = getClientIP(c);
    const session_key = await kv.get(`S:K:${body.client_uuid}:${clientIp}`, "arrayBuffer");
    if (!session_key) {
        Logw(c, `会话无效, UUID: ${body.client_uuid}`);
        return Err(c, "会话无效");
    }

    const decrypt = (data: string) => {
        const data_decoded = base91_decode_to_bytes(data);
        if (!data_decoded) return null;
        const data_decrypted = aes256gcm_decrypt_to_str(new Uint8Array(session_key), data_decoded);
        if (!data_decrypted) return null;
        return data_decrypted;
    };

    // 并行解密所有数据
    const [clientTsSec, tagSigEncoded, binding, productId] = await Promise.all([
        decrypt(body.data_1),
        decrypt(body.data_2),
        decrypt(body.data_3),
        decrypt(body.data_4)
    ]);
    if (!clientTsSec || !tagSigEncoded || !binding || !productId) {
        Logw(c, "数据解密失败");
        return Err(c, "数据错误");
    }


    // 验证时间戳
    const nowSec = Math.floor(Date.now() / 1000);
    const clientSec = Number(clientTsSec);
    if (!Number.isFinite(clientSec)) {
        Logw(c, `时间戳非法: ${clientTsSec}`);
        return Err(c, "时间戳非法");
    }
    const diff = Math.abs(nowSec - clientSec);
    if (diff > 30) {
        Logw(c, `请求已过期, 时间差: ${diff}秒`);
        return Err(c, "请求已过期");
    }


    const clientProductId = Number(productId);
    if (!Number.isFinite(clientProductId)) {
        Logw(c, `产品ID非法: ${productId}`);
        return Err(c, "产品id非法");
    }

    if (!await Product.existsId(kv,clientProductId)) {
        Logw(c, `产品不存在, ID: ${clientProductId}`);
        return Err(c,"不存在的产品");
    }

    const [ok,productKey] = await Product.getKey(kv, clientProductId);
    if (!ok || !productKey) {
        Loge(c, `获取产品密钥失败, ID: ${clientProductId}`);
        return Err(c,"产品错误");
    }


    // 解析 tag_sig - base85 解码
    const tag_sig = base85_decode_to_bytes(tagSigEncoded);
    if (!tag_sig) {
        Logw(c, "License tag_sig Base85解码失败");
        return Err(c, "license格式错误");
    }

    const tag_json = xchacha20poly1305_decrypt_to_str(productKey,tag_sig);
    if (!tag_json) {
        Logw(c, "License解密失败");
        return Err(c, "license错误");
    }

    const LicenseTag = z.object({
        activation_time_point_sec: z.number(),
        use_max_duration: z.number(),
        binding: z.string().min(1),
        code_hash: z.string().min(1),
        product_id: z.number(),
    });
    let tag_obj;
    try {
        const json = JSON.parse(tag_json);
        const result = LicenseTag.safeParse(json);
        if (result.success) {
            tag_obj = result.data;
        }
    } catch {
        tag_obj = null;
    }
    if (!tag_obj) {
        Logw(c, "License标签解析失败");
        return Err(c, "license无效");
    }


    // 验证 binding 是否匹配
    const binding_hash = blake3_digest_from_str(binding);
    if (tag_obj.binding !== binding_hash) {
        Logw(c, "Binding不匹配");
        return Err(c, "binding不匹配");
    }

    // 计算使用时间是否超期
    const usage_duration = nowSec - tag_obj.activation_time_point_sec;
    if (usage_duration > tag_obj.use_max_duration) {
        Logw(c, `License已过期, 已使用: ${usage_duration}秒, 最大: ${tag_obj.use_max_duration}秒`);
        return Err(c, "license已过期");
    }


    const json = JSON.stringify({
        activation_time_point_sec: tag_obj.activation_time_point_sec,
        use_max_duration: tag_obj.use_max_duration,
        binding: tag_obj.binding,
        code_hash: tag_obj.code_hash,
        product_id: tag_obj.product_id,
        tag_sig: base85_encode_from_bytes(tag_sig)
    });

    const json_encrypted = aes256gcm_encrypt_from_str(new Uint8Array(session_key), json);
    if (!json_encrypted) {
        Loge(c, "响应数据加密失败");
        return  Err(c,"服务器错误");
    }


    return Ok(c,base91_encode_from_bytes(json_encrypted));
});


export default api;