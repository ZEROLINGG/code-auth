export class Hash {
    /** SHA-512 */
    static async sha512(data: string): Promise<string> {
        const buffer = new TextEncoder().encode(data);
        const hash = await crypto.subtle.digest('SHA-512', buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    /** SHA-256 */
    static async sha256(data: string): Promise<string> {
        const buffer = new TextEncoder().encode(data);
        const hash = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
    /** SHA-1 */
    static async sha1(data: string): Promise<string> {
        const buffer = new TextEncoder().encode(data);
        const hash = await crypto.subtle.digest('SHA-1', buffer);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}