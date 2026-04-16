export class Base64 {
    /**
     * 将 ArrayBuffer 或 Uint8Array 转换为 Base64 字符串
     * @param buffer - 待转换的 ArrayBuffer 或 Uint8Array
     * @returns Base64 编码的字符串
     */
    static fromBuffer(buffer: ArrayBuffer | Uint8Array): string {
        const bytes = ArrayBuffer.isView(buffer) ? buffer : new Uint8Array(buffer);
        const chunkSize = 0x8000; // 32KB 分块
        let binary = '';
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode(...chunk);
        }
        return btoa(binary);
    }

    /**
     * 将 Base64 字符串转换为 ArrayBuffer
     * @param base64 - Base64 编码的字符串
     * @returns 解码后的 ArrayBuffer
     * @throws 当 Base64 字符串格式无效时抛出错误
     */
    static toArrayBuffer(base64: string): ArrayBuffer {
        try {
            const binary = atob(base64);
            const len = binary.length;
            const bytes = new Uint8Array(len);
            const chunkSize = 0x8000; // 32KB 分块处理
            for (let i = 0; i < len; i += chunkSize) {
                const chunk = binary.slice(i, i + chunkSize);
                for (let j = 0; j < chunk.length; j++) {
                    bytes[i + j] = chunk.charCodeAt(j);
                }
            }
            return bytes.buffer;
        } catch {
            throw new Error('Base64 字符串格式无效');
        }
    }

    /**
     * 将 Base64 字符串转换为 Uint8Array
     * @param base64 - Base64 编码的字符串
     * @returns 解码后的 Uint8Array
     * @throws 当 Base64 字符串格式无效时抛出错误
     */
    static toUint8Array(base64: string): Uint8Array {
        return new Uint8Array(this.toArrayBuffer(base64));
    }

    /**
     * 将字符串转换为 Base64 字符串
     * @param str - 待编码的字符串
     * @returns Base64 编码的字符串
     */
    static fromString(str: string): string {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(str);
        return this.fromBuffer(bytes);
    }

    /**
     * 将 Base64 字符串解码为普通字符串
     * @param base64 - Base64 编码的字符串
     * @returns 解码后的字符串
     * @throws 当 Base64 字符串格式无效时抛出错误
     */
    static toString(base64: string): string {
        const bytes = this.toUint8Array(base64);
        const decoder = new TextDecoder();
        return decoder.decode(bytes);
    }

    /**
     * 将 Uint8Array 或 ArrayBuffer 转换为 Base64 字符串（URL安全版）
     * '+' 替换为 '-', '/' 替换为 '_', 去掉尾部 '='
     * @param buffer - 待转换的 ArrayBuffer 或 Uint8Array
     * @returns URL安全的 Base64 字符串
     */
    static fromBuffer_Url(buffer: ArrayBuffer | Uint8Array): string {
        return this.fromBuffer(buffer)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }

    /**
     * 将 URL安全 Base64 字符串转换为 ArrayBuffer
     * @param base64Url - URL安全 Base64 编码字符串
     * @returns 解码后的 ArrayBuffer
     * @throws 当 Base64 字符串格式无效时抛出错误
     */
    static toArrayBuffer_Url(base64Url: string): ArrayBuffer {
        let base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        // 补齐 '=' 到长度为 4 的倍数
        while (base64.length % 4) {
            base64 += '=';
        }
        return this.toArrayBuffer(base64);
    }

    /**
     * 将字符串转换为 URL安全 Base64 字符串
     * @param str - 待编码的字符串
     * @returns URL安全 Base64 编码字符串
     */
    static fromString_Url(str: string): string {
        const bytes = new TextEncoder().encode(str);
        return this.fromBuffer_Url(bytes);
    }

    /**
     * 将 URL安全 Base64 字符串解码为普通字符串
     * @param base64Url - URL安全 Base64 编码字符串
     * @returns 解码后的字符串
     */
    static toString_Url(base64Url: string): string {
        const bytes = this.toArrayBuffer_Url(base64Url);
        return new TextDecoder().decode(bytes);
    }
}
