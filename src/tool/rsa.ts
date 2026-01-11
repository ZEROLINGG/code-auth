import {Base64} from "./base64";

export class RSA {
    static pemToArrayBuffer(pem: string): ArrayBuffer {
        const base64 = pem
            .replace(/-----BEGIN.*?-----/g, '')
            .replace(/-----END.*?-----/g, '')
            .replace(/\s/g, '');
        return Base64.toArrayBuffer(base64);
    }

    static arrayBufferToPem(buffer: ArrayBuffer, type: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
        const base64 = Base64.fromBuffer(buffer);
        const lines = base64.match(/.{1,64}/g) || [];
        return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
    }

    // ==================== RSA 操作 ====================
    static async generateRSAKeyPair(): Promise<CryptoKeyPair> {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        return keyPair as CryptoKeyPair;
    }

    static async exportPublicKeyPEM(key: CryptoKey): Promise<string> {
        const exported = await crypto.subtle.exportKey('spki', key);
        return this.arrayBufferToPem(exported as ArrayBuffer, 'PUBLIC KEY');
    }

    static async exportPrivateKeyPEM(key: CryptoKey): Promise<string> {
        const exported = await crypto.subtle.exportKey('pkcs8', key);
        return this.arrayBufferToPem(exported as ArrayBuffer, 'PRIVATE KEY');
    }

    static async importPublicKeyPEM(pem: string): Promise<CryptoKey> {
        const keyData = this.pemToArrayBuffer(pem);
        return await crypto.subtle.importKey(
            'spki',
            keyData,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['encrypt']
        );
    }

    static async importPrivateKeyPEM(pem: string): Promise<CryptoKey> {
        const keyData = this.pemToArrayBuffer(pem);
        return await crypto.subtle.importKey(
            'pkcs8',
            keyData,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['decrypt']
        );
    }

    static async rsaEncrypt(plaintext: string, publicKeyPem: string): Promise<string> {
        const publicKey = await this.importPublicKeyPEM(publicKeyPem);
        const data = new TextEncoder().encode(plaintext);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            data
        );
        return Base64.fromBuffer(encrypted);
    }

    static async rsaDecrypt(encryptedB64: string, privateKeyPem: string): Promise<string> {
        const privateKey = await this.importPrivateKeyPEM(privateKeyPem);
        const encryptedData = Base64.toArrayBuffer(encryptedB64);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            encryptedData
        );
        return new TextDecoder().decode(decrypted);
    }
}