// tool/code.ts
import {randomString, kvLock, randomInt, serverT, sleep} from "./tool";
import {Hash} from "./hash";
import {AES} from "./aes";
import {Base64} from "./base64";
import {Product} from "./product";
import {CONFIG} from "../config";


// randomS,prodId使用同样且不包含:的字符集
// prodId有7个字符

/**
 * 按顺序拼接多个 Uint8Array
 * @param parts - 按顺序传入的 Uint8Array
 * @returns 新的 Uint8Array
 */
export function concatUint8Array(...parts: Uint8Array[]): Uint8Array {
    let totalLength = 0;
    for (const part of parts) {
        totalLength += part.length;
    }

    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }

    return result;
}

/**
 * 比较两个 Uint8Array 是否相等
 */
function compareUint8Array(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}


interface ICodeInfo {
    uuid: string;
    bindingHash: string;
    use_expirationTime: number;
    code_expirationTime: number;
    maxAmount: number;
}

type VerifyResult = [success: boolean, productId: string, code_expirationTime: number, duration: number, amount: number];
export type AuthResult = [success: boolean, uuid: string, code_expirationTime: number, use_expirationTime: number, bindingHash: string, remaining: number];

export class Code {
    private static readonly CODE_PREFIX = "C:";
    private static readonly CODE_INFO_PREFIX = "CI:";
    private static readonly COLON_CHAR_CODE = 58;
    private static readonly RANDOM_S_LENGTH = 7;

    /**
     * 生成激活码
     * 结构: Base64( [AES长度(2Bytes)] + [AES密文] + [":过期时间:时长:次数"] )
     * AES密文内容: randomS:productId:mixedU8
     */
    static async _generate(
        aesKey: string,
        productId: string,
        code_expirationDuration: number,
        activationDuration: number,
        maxAmount: number
    ): Promise<string> {
        // 限制最大有效期
        code_expirationDuration = code_expirationDuration > CONFIG.MAX_CODE_VALIDITY_SECONDS ? CONFIG.MAX_CODE_VALIDITY_SECONDS : code_expirationDuration;
        activationDuration = activationDuration > CONFIG.MAX_USE_VALIDITY_SECONDS ? CONFIG.MAX_USE_VALIDITY_SECONDS : activationDuration;

        const randomS = randomString(this.RANDOM_S_LENGTH);
        const s1 = `${randomS}:${productId}`;
        // 明文后缀部分，注意开头包含了冒号
        const s2 = `:${serverT.now() + code_expirationDuration}:${activationDuration}:${maxAmount}`;

        // 计算校验哈希
        const [sha256_1, sha256_2] = await Promise.all([
            Hash.sha256_HexString(s1),
            Hash.sha256_HexString(s2)
        ]);

        const encoder = new TextEncoder();

        // 准备加密数据
        const s1U8 = encoder.encode(s1);
        const colonCharU8 = encoder.encode(":");
        const mixedU8 = (await Hash.sha256_Uint8Array(`${sha256_1}:${sha256_2}`)).slice(16);

        // AES 加密 (randomS:productId:mixedU8)
        const u1_encrypted = await AES.encrypt_ToUint8Array(
            concatUint8Array(s1U8, colonCharU8, mixedU8),
            await AES.getAesKey(aesKey)
        );

        // 构建长度前缀 (2字节, Big Endian)
        // 2字节最大支持 65535 长度，对于激活码场景绰绰有余
        const lenBuffer = new Uint8Array(2);
        new DataView(lenBuffer.buffer).setUint16(0, u1_encrypted.length);

        // 准备后缀数据
        const u2_plaintext = encoder.encode(s2);

        // 最终拼接: [长度] + [密文] + [明文后缀]
        return Base64.fromBuffer(concatUint8Array(lenBuffer, u1_encrypted, u2_plaintext));
    }

    /**
     * 根据产品名生成激活码
     */
    static async gent(
        kv: KVNamespace,
        aesKey: string,
        productName: string,
        expirationPeriod: number,
        activationDuration: number,
        amount: number
    ): Promise<[boolean, string]> {
        const [exists, productId] = await Product.getId(kv, productName);
        if (!exists) return [false, ""];

        const code = await this._generate(aesKey, productId, expirationPeriod, activationDuration, amount);
        return [true, code];
    }

    /**
     * 根据产品ID生成激活码
     */
    static async gentId(
        kv: KVNamespace,
        aesKey: string,
        productId: string,
        expirationPeriod: number,
        activationDuration: number,
        amount: number
    ): Promise<[boolean, string]> {
        if (!(await Product.existsId(kv, productId))) {
            return [false, ""];
        }

        const code = await this._generate(aesKey, productId, expirationPeriod, activationDuration, amount);
        return [true, code];
    }

    /**
     * 验证激活码
     */
    static async verify(aesKey: string, code: string, productId: string): Promise<VerifyResult> {
        try {
            const codeU8 = Base64.toUint8Array(code);

            // 基础长度检查 (至少要有2字节长度头)
            if (codeU8.length < 2) {
                return [false, "", 0, 0, 0];
            }

            // 1. 读取密文长度 (前2字节)
            // 注意：使用 byteOffset 确保在切片(subarray)上操作正确
            const cipherLen = new DataView(codeU8.buffer, codeU8.byteOffset, codeU8.byteLength).getUint16(0);

            // 2. 边界检查
            // 结构: [2byte Length] + [CipherBytes] + [PlaintextBytes]
            if (codeU8.length < 2 + cipherLen) {
                return [false, "", 0, 0, 0];
            }

            // 3. 切割密文和明文
            const u1_encrypted = codeU8.slice(2, 2 + cipherLen);
            const u2_plaintext = codeU8.slice(2 + cipherLen); // 这里开头应该是 ":"

            // 4. 解析明文后缀
            // 格式: :code_expirationTime:activationDuration:amount
            const s2 = new TextDecoder().decode(u2_plaintext);
            // 简单校验 s2 必须以 : 开头
            if (!s2.startsWith(":")) {
                return [false, "", 0, 0, 0];
            }

            const s2Parts = s2.split(":"); // ["", "time", "duration", "amount"]
            if (s2Parts.length < 4) {
                return [false, "", 0, 0, 0];
            }

            const code_expirationTime = parseInt(s2Parts[1], 10);
            const activationDuration = parseInt(s2Parts[2], 10);
            const maxAmount = parseInt(s2Parts[3], 10);

            // 5. 验证过期时间 (明文层先验证，减少解密开销)
            if (code_expirationTime < serverT.now()) {
                return [false, "", 0, 0, 0];
            }

            // 6. 解密
            const decryptedU8 = await AES.decrypt_ToUint8Array(u1_encrypted, await AES.getAesKey(aesKey));

            // 7. 解析解密后数据: randomS:prodId:mixedU8
            // 查找冒号分割
            const firstColonIndex = decryptedU8.indexOf(this.COLON_CHAR_CODE);
            if (firstColonIndex === -1) return [false, "", 0, 0, 0];

            const secondColonIndex = decryptedU8.indexOf(this.COLON_CHAR_CODE, firstColonIndex + 1);
            if (secondColonIndex === -1) return [false, "", 0, 0, 0];

            const randomS = new TextDecoder().decode(decryptedU8.slice(0, firstColonIndex));
            const prodId = new TextDecoder().decode(decryptedU8.slice(firstColonIndex + 1, secondColonIndex));
            const mixedU8 = decryptedU8.slice(secondColonIndex + 1);

            // 8. 验证 ProductID
            if (prodId !== productId) {
                return [false, "", 0, 0, 0];
            }

            // 9. 验证完整性哈希
            const [sha256_1, sha256_2] = await Promise.all([
                Hash.sha256_HexString(`${randomS}:${prodId}`),
                Hash.sha256_HexString(s2)
            ]);
            const recombinedU8 = (await Hash.sha256_Uint8Array(`${sha256_1}:${sha256_2}`)).slice(16);

            if (!compareUint8Array(mixedU8, recombinedU8)) {
                return [false, "", 0, 0, 0];
            }

            return [true, productId, code_expirationTime, activationDuration, maxAmount];
        } catch (e) {
            // 发生任何解析错误或解密错误均返回失败
            return [false, "", 0, 0, 0];
        }
    }

    /**
     * 激活码认证
     */
    static async auth(
        kv: KVNamespace,
        aesKey: string,
        code: string,
        productId: string,
        binding: string = ""
    ): Promise<AuthResult> {
        // 使用 Code 原文哈希作为 Key，确保唯一性
        const key = `${this.CODE_PREFIX}${await Hash.sha256_HexString(code)}`;
        const lock = await kvLock.waitAndAcquire(kv, key, 10 * 1000);

        if (!lock) {
            await sleep(randomInt(500, 700));
            return [false, "", 0, 0, "", 0];
        }

        try {
            // 验证激活码
            const [valid, _, code_expirationTime, activationDuration, maxAmount] = await this.verify(aesKey, code, productId);

            if (!valid) {
                await sleep(randomInt(100, 400));
                return [false, "", 0, 0, "", 0];
            }

            // 获取使用次数
            const usedStr = await kv.get(key);
            const used = usedStr ? parseInt(usedStr, 10) : 0;

            // 检查是否超过使用次数
            if (used >= maxAmount) {
                return [false, "", 0, 0, "", 0];
            }

            // 创建新的使用记录
            const newUsed = used + 1;
            const uuid = crypto.randomUUID();
            const bindingHash = await Hash.sha256_HexString(`${binding}:${key}:${uuid}:${aesKey}`);
            const use_expirationTime = serverT.now() + activationDuration;

            const codeInfo: ICodeInfo = {
                uuid,
                bindingHash,
                use_expirationTime,
                code_expirationTime,
                maxAmount
            };

            await Promise.all([
                // 激活码使用记录 TTL 设置为激活码本身的有效期
                kv.put(key, newUsed.toString(), { expirationTtl: CONFIG.MAX_CODE_VALIDITY_SECONDS}),
                // 授权信息记录 TTL 设置为本次激活的时长
                kv.put(`${this.CODE_INFO_PREFIX}${uuid}`,
                    JSON.stringify(codeInfo), { expirationTtl: activationDuration }
                )
            ]);

            return [true, uuid, code_expirationTime, use_expirationTime, bindingHash, maxAmount - newUsed];
        } catch {
            return [false, "", 0, 0, "", 0];
        } finally {
            await kvLock.release(kv, key);
        }
    }

    /**
     * 后期认证 (验证已激活的会话)
     */
    static async authAgain(
        kv: KVNamespace,
        uuid: string,
        bindingHash: string
    ): Promise<AuthResult> {
        try {
            // 获取认证信息
            const ciStr = await kv.get(`${this.CODE_INFO_PREFIX}${uuid}`);
            if (!ciStr) {
                await sleep(randomInt(300, 700)); // 防止计时攻击
                return [false, "", 0, 0, "", 0];
            }

            const codeInfo = JSON.parse(ciStr) as ICodeInfo;

            // 验证认证信息
            if (
                codeInfo.uuid !== uuid ||
                codeInfo.bindingHash !== bindingHash ||
                codeInfo.use_expirationTime <= serverT.now()
            ) {
                return [false, "", 0, 0, "", 0];
            }

            // 后期认证不需要知道当初的激活码还能用几次，返回 0
            return [true, uuid, codeInfo.code_expirationTime, codeInfo.use_expirationTime, bindingHash, 0];
        } catch {
            return [false, "", 0, 0, "", 0];
        }
    }
}