import {CONFIG} from "../config";
import {RSA} from "./rsa";

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}
export function randomInt(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

export class kvLock {
    /**
     * 尝试获取锁
     * @param kv KVNamespace
     * @param name 锁名
     * @returns 是否成功获得锁
     */
    static async acquire(kv: KVNamespace, name: string): Promise<boolean> {
        const key = `L:${name}`;
        if (await kv.get(key) === "true") return false;
        await kv.put(key, "true");
        return true;

    }
    /**
     * 释放锁
     */
    static async release(kv: KVNamespace, name: string) {
        const key = `L:${name}`;
        await kv.delete(key);
    }
    /**
     * 阻塞式尝试获取锁
     */
    static async waitAndAcquire(kv: KVNamespace, name: string, retryDelay: number = 100): Promise<void> {
        while (!(await kvLock.acquire(kv, name))) {
            await new Promise(res => setTimeout(res, retryDelay)); // 等待重试
        }
    }
}

export function randomString(length: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charsLen = chars.length;
    const result = [];
    const array = new Uint8Array(length * 2); // 多生成一些字节以应对拒绝采样

    while (result.length < length) {
        crypto.getRandomValues(array);
        for (const b of array) {
            if (b < 256 - (256 % charsLen)) { // 拒绝掉 248-255 的字节
                result.push(chars[b % charsLen]);
                if (result.length === length) break;
            }
        }
    }
    return result.join('');
}

export function generateUUID(): string {
    return crypto.randomUUID();
}

/**
 * 确保 RSA 密钥对存在于 KV 存储中。
 * 如果不存在（如首次运行或密钥过期），则生成新的密钥对并保存。
 * 这些密钥用于加密客户端和服务器之间的通信。
 */
export async function ensureRSAKeys(kv: KVNamespace): Promise<void> {
    const existingPubKey = await kv.get('rsa_pub_key_pem');
    // 如果公钥不存在，说明需要重新生成密钥对
    if (!existingPubKey) {
        const keyPair = await RSA.generateRSAKeyPair();
        const pubKeyPem = await RSA.exportPublicKeyPEM(keyPair.publicKey);
        const priKeyPem = await RSA.exportPrivateKeyPEM(keyPair.privateKey);

        await kv.put('rsa_pub_key_pem', pubKeyPem, { expirationTtl: CONFIG.RSA_KEY_UPDATE_TIME });
        await kv.put('rsa_pri_key_pem', priKeyPem, { expirationTtl: CONFIG.RSA_KEY_UPDATE_TIME });
    }
}

/**
 * 获取客户端真实 IP 地址
 * 兼容 Cloudflare Workers 标准头和常见的代理头
 */
export function getClientIP(request: Request): string {
    return request.headers.get('CF-Connecting-IP') || // Cloudflare 提供的最准确 IP
        request.headers.get('X-Real-IP') ||
        request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
        '0.0.0.0';
}

export const serverT = {
    now: (): number => {
        const nowMs = Date.now();
        return Math.floor(nowMs / 1000) - CONFIG.ServerBaseTimestamp; // 秒级相对时间
    },
    toDate: (T: number): Date => {
        return new Date((T + CONFIG.ServerBaseTimestamp) * 1000);
    },
    fromDate: (date: Date): number => {
        return Math.floor(date.getTime() / 1000) - CONFIG.ServerBaseTimestamp;
    }
};

export async function authSuperAdmin(
    request: Request,
    SUPER_ADMIN_KEY: string,
    adminIp: string
): Promise<boolean> {
    // 1. 验证 Admin Key (通过自定义头 X-Authorization-A 传递)
    const xAuth = request.headers.get('X-Authorization-A') || '';
    if (!xAuth || xAuth !== SUPER_ADMIN_KEY) {
        console.log('Admin auth failed: Invalid key');
        return false;
    }

    const clientIp = getClientIP(request);
    // 3. IP 白名单验证
    // adminIp 可以是单个 IP 或逗号分隔的多个 IP (如 "1.1.1.1, 2.2.2.2")
    const allowedIPs = adminIp.split(',').map(ip => ip.trim());
    return allowedIPs.includes(clientIp);
}

