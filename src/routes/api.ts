import { Hono, Context } from "hono";
import { generateUUID, ensureRSAKeys } from "../tool/tool";
import { CONFIG } from "../config";
import { RSA } from "../tool/rsa";
import { Code } from "../tool/code";

// ═══════════════════════════════════════════════════════════
//                        类型定义
// ═══════════════════════════════════════════════════════════

interface KeyExchangeRequest {
    client_pub_key_pem: string;
}

interface AuthRegCodeRequest {
    client_uuid: string;
    data_c: string;
    data_i: string;
    data_b: string;
}

interface AuthAgainRequest {
    client_uuid: string;
    data_c: string;
    data_u: string;
    data_b?: string;
}

interface SessionContext {
    serverPriPem: string;
    clientPubPem: string;
}

// ═══════════════════════════════════════════════════════════
//                        自定义错误
// ═══════════════════════════════════════════════════════════

class ApiError extends Error {
    readonly statusCode: number;
    readonly code: string;

    constructor(message: string, statusCode = 400, code = "ERROR") {
        super(message);
        this.name = "ApiError";
        this.statusCode = statusCode;
        this.code = code;
    }

    static sessionExpired(): ApiError {
        return new ApiError("Session expired. Please refresh.", 401, "SESSION_EXPIRED");
    }

    static invalidFormat(field: string): ApiError {
        return new ApiError(`Invalid ${field} format`, 400, "INVALID_FORMAT");
    }

    static missingField(field: string): ApiError {
        return new ApiError(`Missing required field: ${field}`, 400, "MISSING_FIELD");
    }

    static serverError(message = "Internal server error"): ApiError {
        return new ApiError(message, 500, "SERVER_ERROR");
    }

    static timestampExpired(): ApiError {
        return new ApiError("Request timestamp expired", 400, "TIMESTAMP_EXPIRED");
    }
}

// ═══════════════════════════════════════════════════════════
//                        工具函数
// ═══════════════════════════════════════════════════════════

const api = new Hono<{ Bindings: CloudflareBindings }>();

/** 获取 KV 实例 */
function getKV(c: Context<{ Bindings: CloudflareBindings }>): KVNamespace {
    return c.env.AUTH_KV;
}

/** 统一成功响应 */
function ok(c: Context, data?: Record<string, unknown>): Response {
    return c.json({ status: "ok", ...data });
}

/** 统一错误响应 */
function fail(c: Context, error: ApiError | string, statusCode = 400): Response {
    const message = error instanceof ApiError ? error.message : error;
    const code = error instanceof ApiError ? error.statusCode : statusCode;
    return c.json({ status: "error", message , code});
}

/** 验证会话有效性并获取密钥对 */
async function getSessionContext(kv: KVNamespace, clientUuid: string): Promise<SessionContext> {
    const [serverPriPem, clientPubPem] = await Promise.all([
        kv.get("rsa_pri_key_pem"),
        kv.get(`S:${clientUuid}`)
    ]);

    if (!serverPriPem) {
        throw ApiError.serverError("Server private key not found");
    }

    if (!clientPubPem) {
        throw ApiError.sessionExpired();
    }

    return { serverPriPem, clientPubPem };
}

/** RSA 解密封装 */
async function decrypt(ciphertext: string, privateKey: string): Promise<string> {
    try {
        return await RSA.rsaDecrypt(ciphertext, privateKey);
    } catch (e) {
        console.error("Decryption failed:", e);
        throw ApiError.invalidFormat("encrypted data");
    }
}

/** RSA 加密封装 */
async function encrypt(plaintext: string, publicKey: string): Promise<string> {
    try {
        return await RSA.rsaEncrypt(plaintext, publicKey);
    } catch (e) {
        console.error("Encryption failed:", e);
        throw ApiError.serverError("Response encryption failed");
    }
}

/** 解析带时间戳的数据 (格式: value:timestamp) */
function parseTimestampedData(data: string): { value: string; timestamp: number } {
    const lastColonIdx = data.lastIndexOf(":");
    if (lastColonIdx === -1) {
        throw ApiError.invalidFormat("data");
    }

    const value = data.substring(0, lastColonIdx);
    const timestamp = parseInt(data.substring(lastColonIdx + 1), 10);

    if (isNaN(timestamp)) {
        throw ApiError.invalidFormat("timestamp");
    }

    return { value, timestamp };
}

/** 验证时间戳是否在允许范围内 */
function validateTimestamp(timestamp: number): void {
    const drift = Math.abs(Date.now() - timestamp);
    if (drift > CONFIG.TIMESTAMP_TOLERANCE_MS) {
        throw ApiError.timestampExpired();
    }
}

/** 构建认证结果字符串 */
function buildAuthResult(success: boolean, uuid: string, remaining: number): string {
    return `${success}:${uuid}:${remaining}`;
}

/** 验证必填字段 - 修复类型问题 */
function validateRequiredFields(body: object, requiredFields: string[]): void {
    const record = body as Record<string, unknown>;
    for (const field of requiredFields) {
        if (!record[field]) {
            throw ApiError.missingField(field);
        }
    }
}

// ═══════════════════════════════════════════════════════════
//                          中间件
// ═══════════════════════════════════════════════════════════

/** 全局错误处理 + RSA 密钥初始化 */
api.use("*", async (c, next) => {
    try {
        await ensureRSAKeys(getKV(c));
        await next();
    } catch (e) {
        if (e instanceof ApiError) {
            return fail(c, e, e.statusCode);
        }
        console.error("Unhandled error:", e);
        return fail(c, ApiError.serverError(), 500);
    }
});

// ═══════════════════════════════════════════════════════════
//                        API 路由
// ═══════════════════════════════════════════════════════════

/**
 * [POST] /pub/key/exc - RSA 公钥交换接口
 */
api.post("/pub/key/exc", async (c) => {
    const kv = getKV(c);
    const body = await c.req.json<KeyExchangeRequest>();

    const clientPubKeyPem = body.client_pub_key_pem?.trim();
    if (!clientPubKeyPem) {
        throw ApiError.missingField("client_pub_key_pem");
    }

    // 验证公钥格式
    try {
        await RSA.importPublicKeyPEM(clientPubKeyPem);
    } catch {
        throw ApiError.invalidFormat("client public key");
    }

    // 获取服务器公钥
    const serverPubKeyPem = await kv.get("rsa_pub_key_pem");
    if (!serverPubKeyPem) {
        throw ApiError.serverError("Server public key not available");
    }

    // 生成会话
    const clientUuid = generateUUID();
    await kv.put(`S:${clientUuid}`, clientPubKeyPem, {
        expirationTtl: CONFIG.CLIENT_KEY_TTL
    });

    return ok(c, {
        client_uuid: clientUuid,
        server_pub_key_pem: serverPubKeyPem
    });
});

/**
 * [POST] /auth/reg/code - 核心验证接口
 */
api.post("/auth/reg/code", async (c) => {
    const kv = getKV(c);
    const body = await c.req.json<AuthRegCodeRequest>();

    // 验证必填字段
    validateRequiredFields(body, ["client_uuid", "data_c", "data_i", "data_b"]);

    // 获取会话上下文
    const { serverPriPem, clientPubPem } = await getSessionContext(kv, body.client_uuid);

    let success = false;
    let uuid = "";
    let remaining = 0;

    try {
        // 并行解密所有数据
        const [dataC, productId, binding] = await Promise.all([
            decrypt(body.data_c, serverPriPem),
            decrypt(body.data_i, serverPriPem),
            decrypt(body.data_b, serverPriPem)
        ]);

        // 解析并验证时间戳
        const { value: code, timestamp } = parseTimestampedData(dataC);
        validateTimestamp(timestamp);

        // 执行认证 - 直接解构，移除冗余变量
        [success, uuid, remaining] = await Code.auth(
            kv,
            c.env.SERVER_KEY,
            code,
            productId,
            binding
        );

    } catch (e) {
        if (e instanceof ApiError) {
            throw e;
        }
        console.error("Auth processing error:", e);
    }

    // 加密响应
    const resultStr = buildAuthResult(success, uuid, remaining);
    const encryptedData = await encrypt(resultStr, clientPubPem);

    return ok(c, { data: encryptedData });
});

/**
 * [POST] /auth/again/reg/code - 重新认证接口
 */
api.post("/auth/again/reg/code", async (c) => {
    const kv = getKV(c);
    const body = await c.req.json<AuthAgainRequest>();

    // 验证必填字段
    validateRequiredFields(body, ["client_uuid", "data_c", "data_u"]);

    // 获取会话上下文
    const { serverPriPem, clientPubPem } = await getSessionContext(kv, body.client_uuid);

    // 并行解密 - 修复 await 问题
    const code = await decrypt(body.data_c, serverPriPem);
    const activationUuid = await decrypt(body.data_u, serverPriPem);
    const binding = body.data_b ? await decrypt(body.data_b, serverPriPem) : "";

    // 执行重新认证
    const [success, expirationOrUuid, remaining] = await Code.authAgain(
        kv,
        code,
        activationUuid,
        binding
    );

    // 加密响应
    const resultStr = buildAuthResult(success, expirationOrUuid, remaining);
    const encryptedData = await encrypt(resultStr, clientPubPem);

    return ok(c, { data: encryptedData });
});

export default api;