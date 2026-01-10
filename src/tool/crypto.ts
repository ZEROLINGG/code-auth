/**
 * 加密工具模块 - 使用 Web Crypto API
 */

// ==================== 工具函数 ====================

function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const base64 = pem
        .replace(/-----BEGIN.*?-----/g, '')
        .replace(/-----END.*?-----/g, '')
        .replace(/\s/g, '');
    return base64ToArrayBuffer(base64);
}

function arrayBufferToPem(buffer: ArrayBuffer, type: 'PUBLIC KEY' | 'PRIVATE KEY'): string {
    const base64 = arrayBufferToBase64(buffer);
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${type}-----\n${lines.join('\n')}\n-----END ${type}-----`;
}

// ==================== RSA 操作 ====================

export async function generateRSAKeyPair(): Promise<CryptoKeyPair> {
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

    // 类型断言：RSA-OAEP 总是返回 CryptoKeyPair
    return keyPair as CryptoKeyPair;
}

export async function exportPublicKeyPEM(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key);
    // 类型断言：'spki' 格式返回 ArrayBuffer
    return arrayBufferToPem(exported as ArrayBuffer, 'PUBLIC KEY');
}

export async function exportPrivateKeyPEM(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('pkcs8', key);
    // 类型断言：'pkcs8' 格式返回 ArrayBuffer
    return arrayBufferToPem(exported as ArrayBuffer, 'PRIVATE KEY');
}

export async function importPublicKeyPEM(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
        'spki',
        keyData,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt']
    );
}

export async function importPrivateKeyPEM(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
        'pkcs8',
        keyData,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['decrypt']
    );
}

export async function rsaEncrypt(plaintext: string, publicKeyPem: string): Promise<string> {
    const publicKey = await importPublicKeyPEM(publicKeyPem);
    const data = new TextEncoder().encode(plaintext);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        data
    );
    return arrayBufferToBase64(encrypted);
}

export async function rsaDecrypt(encryptedB64: string, privateKeyPem: string): Promise<string> {
    const privateKey = await importPrivateKeyPEM(privateKeyPem);
    const encryptedData = base64ToArrayBuffer(encryptedB64);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedData
    );
    return new TextDecoder().decode(decrypted);
}

// ==================== AES-GCM 操作 ====================

export async function generateAESKey(): Promise<ArrayBuffer> {
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    // 类型断言：AES-GCM 返回单个 CryptoKey
    const exported = await crypto.subtle.exportKey('raw', key as CryptoKey);
    // 类型断言：'raw' 格式返回 ArrayBuffer
    return exported as ArrayBuffer;
}

export async function aesEncrypt(plaintext: string, keyBytes: ArrayBuffer): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );

    // 格式: iv(12) + ciphertext+tag
    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);

    return arrayBufferToBase64(result.buffer);
}

export async function aesDecrypt(encryptedB64: string, keyBytes: ArrayBuffer): Promise<string> {
    const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    const data = new Uint8Array(base64ToArrayBuffer(encryptedB64));

    if (data.length < 28) {
        throw new Error('Invalid encrypted data');
    }

    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}

// ==================== 哈希操作 ====================

export async function sha256(data: string): Promise<string> {
    const buffer = new TextEncoder().encode(data);
    const hash = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

