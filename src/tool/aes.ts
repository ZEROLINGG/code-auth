import {Base64} from "./base64";

/**
 * AES 加密工具类
 * 提供基于 AES-GCM 的加密、解密功能
 */
export class AES {
    // 常量定义
    static CRYPTO_CONFIG = {
        IV_LENGTH: 12,
        MIN_ENCRYPTED_LENGTH: 28, // IV(12) + tag(16)
        AES_KEY_LENGTH: 256,
        ALGORITHM: 'AES-GCM',
        HASH_ALGORITHM: 'SHA-256',
        HKDF_SALT: 'license-system',
        HKDF_INFO: 'activation-code',
    } as const;

// 缓存变量
    static cachedAesKeyBuffer: ArrayBuffer | null = null;
    static cachedServerKey: string | null = null;


    /**
     * 从服务器密钥派生 AES 密钥（使用 HKDF）
     * @param serverKey - 服务器提供的原始密钥字符串
     * @returns AES 密钥的 ArrayBuffer
     * @throws 当密钥派生失败时抛出错误
     */
    static async getAesKey(serverKey: string): Promise<ArrayBuffer> {
        // 检查缓存
        if (this.cachedAesKeyBuffer && this.cachedServerKey === serverKey) {
            return this.cachedAesKeyBuffer;
        }

        try {
            // 导入基础密钥
            const baseKey = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(serverKey),
                'HKDF',
                false,
                ['deriveKey']
            );

            // 使用 HKDF 派生 AES 密钥
            const aesKey = await crypto.subtle.deriveKey(
                {
                    name: 'HKDF',
                    hash: this.CRYPTO_CONFIG.HASH_ALGORITHM,
                    salt: new TextEncoder().encode(this.CRYPTO_CONFIG.HKDF_SALT),
                    info: new TextEncoder().encode(this.CRYPTO_CONFIG.HKDF_INFO),
                },
                baseKey,
                {
                    name: this.CRYPTO_CONFIG.ALGORITHM,
                    length: this.CRYPTO_CONFIG.AES_KEY_LENGTH,
                },
                true,
                ['encrypt', 'decrypt']
            );

            // 导出并缓存密钥
            this.cachedAesKeyBuffer = (await crypto.subtle.exportKey('raw', aesKey)) as ArrayBuffer;
            this.cachedServerKey = serverKey;

            return this.cachedAesKeyBuffer;
        } catch (error) {
            throw new Error(`密钥派生失败: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * 使用 AES-GCM 加密数据
     * @param plaintext - 待加密的明文字符串
     * @param keyBytes - AES 密钥的 ArrayBuffer
     * @returns 包含 IV + 密文 + Tag 的 Uint8Array
     * @throws 当加密失败时抛出错误
     */
    static async encrypt(plaintext: string, keyBytes: ArrayBuffer): Promise<Uint8Array> {
        try {
            // 导入密钥
            const key = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: this.CRYPTO_CONFIG.ALGORITHM },
                false,
                ['encrypt']
            );

            // 生成随机 IV
            const iv = crypto.getRandomValues(new Uint8Array(this.CRYPTO_CONFIG.IV_LENGTH));

            // 编码明文
            const data = new TextEncoder().encode(plaintext);

            // 执行加密
            const encrypted = await crypto.subtle.encrypt(
                { name: this.CRYPTO_CONFIG.ALGORITHM, iv },
                key,
                data
            );

            // 组合 IV 和密文
            const result = new Uint8Array(iv.length + encrypted.byteLength);
            result.set(iv, 0);
            result.set(new Uint8Array(encrypted), iv.length);

            return result;
        } catch (error) {
            throw new Error(`加密失败: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * 使用 AES-GCM 加密数据并返回 Base64 字符串
     * @param plaintext - 待加密的明文字符串
     * @param keyBytes - AES 密钥的 ArrayBuffer
     * @returns Base64 编码的加密数据
     * @throws 当加密或编码失败时抛出错误
     */
    static async encryptToBase64(plaintext: string, keyBytes: ArrayBuffer): Promise<string> {
        const encrypted = await AES.encrypt(plaintext, keyBytes);
        return Base64.fromBuffer(encrypted);
    }

    /**
     * 解密 AES-GCM 加密的数据
     * @param encrypted - Base64 字符串或 Uint8Array 格式的加密数据
     * @param keyBytes - AES 密钥的 ArrayBuffer
     * @returns 解密后的明文字符串
     * @throws 当解密失败或数据格式无效时抛出错误
     */
    static async decrypt(encrypted: Uint8Array | string, keyBytes: ArrayBuffer): Promise<string> {
        try {
            // 导入密钥
            const key = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: this.CRYPTO_CONFIG.ALGORITHM },
                false,
                ['decrypt']
            );

            // 转换数据格式
            let data: Uint8Array;
            if (typeof encrypted === 'string') {
                data = new Uint8Array(Base64.toArrayBuffer(encrypted));
            } else {
                data = encrypted;
            }

            // 验证数据长度
            if (data.length < this.CRYPTO_CONFIG.MIN_ENCRYPTED_LENGTH) {
                throw new Error('加密数据长度无效，数据可能已损坏');
            }

            // 提取 IV 和密文
            const iv = data.slice(0, this.CRYPTO_CONFIG.IV_LENGTH);
            const ciphertext = data.slice(this.CRYPTO_CONFIG.IV_LENGTH);

            // 执行解密
            const decrypted = await crypto.subtle.decrypt(
                { name: this.CRYPTO_CONFIG.ALGORITHM, iv },
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error(`解密失败: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * 清除缓存的密钥
     * 用于安全地清理敏感数据
     */
    static clearCache(): void {
        this.cachedAesKeyBuffer = null;
        this.cachedServerKey = null;
    }


}


