export class Hash {
    /**
     * 将输入数据转换为 Uint8Array
     */
    private static toUint8Array(data: string | ArrayBuffer | Uint8Array): Uint8Array {
        if (typeof data === 'string') {
            return new TextEncoder().encode(data);
        } else if (data instanceof ArrayBuffer) {
            return new Uint8Array(data);
        } else {
            return new Uint8Array(data);
        }
    }

    /**
     * 将 ArrayBuffer 转换为十六进制字符串
     */
    private static arrayBufferToHex(buffer: ArrayBuffer): string {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /** SHA-512 */
    static async sha512_HexString(data: string | ArrayBuffer | Uint8Array): Promise<string> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-512', buffer);
        return this.arrayBufferToHex(hash);
    }

    /** SHA-512 返回 Uint8Array */
    static async sha512_Uint8Array(data: string | ArrayBuffer | Uint8Array): Promise<Uint8Array> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-512', buffer);
        return new Uint8Array(hash);
    }

    /** SHA-256 */
    static async sha256_HexString(data: string | ArrayBuffer | Uint8Array): Promise<string> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-256', buffer);
        return this.arrayBufferToHex(hash);
    }

    /** SHA-256 返回 Uint8Array */
    static async sha256_Uint8Array(data: string | ArrayBuffer | Uint8Array): Promise<Uint8Array> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-256', buffer);
        return new Uint8Array(hash);
    }

    /** SHA-1 */
    static async sha1_HexString(data: string | ArrayBuffer | Uint8Array): Promise<string> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-1', buffer);
        return this.arrayBufferToHex(hash);
    }

    /** SHA-1 返回 Uint8Array */
    static async sha1_Uint8Array(data: string | ArrayBuffer | Uint8Array): Promise<Uint8Array> {
        const buffer = this.toUint8Array(data);
        const hash = await crypto.subtle.digest('SHA-1', buffer);
        return new Uint8Array(hash);
    }
}