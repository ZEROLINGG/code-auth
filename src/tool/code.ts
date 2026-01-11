// tool/code.ts
import {randomString, kvLock, randomInt, serverT, sleep} from "./tool";
import {Hash} from "./hash";
import {AES} from "./aes";
import {Base64} from "./base64";

interface IProduct {
    name: string;
    id: string;
}

interface ICodeInfo {
    uuid: string;
    binding: string;
    expirationTime: number;
    amount: number;
}

type VerifyResult = [success: boolean, productId: string, duration: number, amount: number];
type AuthResult = [success: boolean, uuid: string, remaining: number];

export class Product {
    private static readonly PRODUCT_KEY = "product";
    private static readonly PRODUCT_ID_LENGTH = 12;

    /**
     * 设置/添加产品
     */
    static async set(kv: KVNamespace, name: string): Promise<[boolean, string]> {
        name = name.trim();
        if (!name) return [false, ""];

        await kvLock.waitAndAcquire(kv, name);
        try {
            const products = await this.gets(kv);

            // 检查产品名是否已存在
            if (products.some(p => p.name === name)) {
                return [false, ""];
            }

            const id = randomString(this.PRODUCT_ID_LENGTH);
            products.push({ name, id });
            await kv.put(this.PRODUCT_KEY, JSON.stringify(products));

            return [true, id];
        } finally {
            await kvLock.release(kv, name);
        }
    }

    /**
     * 获取单个产品
     */
    static async get(kv: KVNamespace, name: string): Promise<[boolean, string]> {
        name = name.trim();
        if (!name) return [false, ""];

        const products = await this.gets(kv);
        const product = products.find(p => p.name === name);
        return product ? [true, product.id] : [false, ""];
    }

    /**
     * 获取所有产品
     */
    static async gets(kv: KVNamespace): Promise<IProduct[]> {
        const productJson = await kv.get(this.PRODUCT_KEY);
        if (!productJson) return [];

        try {
            return JSON.parse(productJson) as IProduct[];
        } catch {
            return [];
        }
    }

    /**
     * 判断产品名是否存在
     */
    static async existsName(kv: KVNamespace, name: string): Promise<boolean> {
        name = name.trim();
        if (!name) return false;

        const products = await this.gets(kv);
        return products.some(p => p.name === name);
    }

    /**
     * 判断产品 ID 是否存在
     */
    static async existsId(kv: KVNamespace, id: string): Promise<boolean> {
        id = id.trim();
        if (!id) return false;

        const products = await this.gets(kv);
        return products.some(p => p.id === id);
    }
}

export class Code {
    private static readonly CODE_PREFIX = "C:";
    private static readonly CODE_INFO_PREFIX = "CI:";
    private static readonly COLON_CHAR_CODE = 58;
    private static readonly RANDOM_S_LENGTH = 10;

    /**
     * 生成激活码
     */
    private static async _generate(
        aesKey: string,
        productId: string,
        expirationPeriod: number,
        activationDuration: number,
        amount: number
    ): Promise<string> {
        const randomS = randomString(this.RANDOM_S_LENGTH);
        const s1 = `${randomS}:${productId}`;
        const s2 = `:${serverT.now() + expirationPeriod}:${activationDuration}:${amount}`;

        const [sha256_1, sha256_2] = await Promise.all([
            Hash.sha256(s1),
            Hash.sha256(s2)
        ]);

        const mixed = await Hash.sha256(`${sha256_1}:${sha256_2}`);
        const plaintext = `${s1}:${mixed}`;

        const encoder = new TextEncoder();
        const u1 = await AES.encrypt(plaintext, await AES.getAesKey(aesKey));
        const u2 = encoder.encode(s2);

        const codeU8 = new Uint8Array(u1.length + u2.length);
        codeU8.set(u1, 0);
        codeU8.set(u2, u1.length);

        return Base64.fromBuffer(codeU8);
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
        const [exists, productId] = await Product.get(kv, productName);
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
     * 查找第n个冒号的位置（从右向左）
     */
    private static findNthColonFromEnd(data: Uint8Array, n: number): number {
        let colonCount = 0;
        for (let i = data.length - 1; i >= 0; i--) {
            if (data[i] === this.COLON_CHAR_CODE) {
                colonCount++;
                if (colonCount === n) return i;
            }
        }
        return -1;
    }

    /**
     * 验证激活码
     */
    static async verify(aesKey: string, code: string, productId: string): Promise<VerifyResult> {
        try {
            const codeU8 = Base64.toUint8Array(code);
            const splitIndex = this.findNthColonFromEnd(codeU8, 3);

            if (splitIndex === -1) {
                return [false, "", 0, 0];
            }

            const u1 = codeU8.slice(0, splitIndex);
            const u2 = codeU8.slice(splitIndex);
            const s2 = new TextDecoder().decode(u2);

            // 解密并验证
            const decrypted = await AES.decrypt(u1, await AES.getAesKey(aesKey));
            const parts = decrypted.split(":");

            if (parts.length < 3) {
                return [false, "", 0, 0];
            }

            const [randomS, prodId, mixed] = parts;

            // 验证产品 ID
            if (prodId !== productId) {
                return [false, "", 0, 0];
            }

            // 解析时间信息
            const s2Parts = s2.split(":");
            if (s2Parts.length < 4) {
                return [false, "", 0, 0];
            }

            const expirationTime = parseInt(s2Parts[1], 10);
            const activationDuration = parseInt(s2Parts[2], 10);
            const amount = parseInt(s2Parts[3], 10);

            // 检查是否过期
            if (expirationTime < serverT.now()) {
                return [false, "", 0, 0];
            }

            // 验证哈希
            const [sha256_1, sha256_2] = await Promise.all([
                Hash.sha256(`${randomS}:${prodId}`),
                Hash.sha256(s2)
            ]);
            const recombined = await Hash.sha256(`${sha256_1}:${sha256_2}`);

            if (recombined !== mixed) {
                return [false, "", 0, 0];
            }

            return [true, productId, activationDuration, amount];
        } catch {
            return [false, "", 0, 0];
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
        const key = `${this.CODE_PREFIX}${await Hash.sha256(code)}`;
        const lock = await kvLock.acquire(kv, key);

        if (!lock) {
            await sleep(randomInt(500, 700));
            return [false, "", 0];
        }

        try {
            // 验证激活码
            const [valid, , duration, maxAmount] = await this.verify(aesKey, code, productId);

            if (!valid) {
                await sleep(randomInt(100, 400));
                return [false, "", 0];
            }

            // 获取使用次数
            const usedStr = await kv.get(key);
            const used = usedStr ? parseInt(usedStr, 10) : 0;

            // 检查是否超过使用次数
            if (used >= maxAmount) {
                return [false, "", 0];
            }

            // 创建新的使用记录
            const newUsed = used + 1;
            const uuid = crypto.randomUUID();
            const bindingHash = await Hash.sha256(binding + key);
            const expirationTime = serverT.now() + duration;

            const codeInfo: ICodeInfo = {
                uuid,
                binding: bindingHash,
                expirationTime,
                amount: maxAmount
            };

            await Promise.all([
                kv.put(key, newUsed.toString()),
                kv.put(`${this.CODE_INFO_PREFIX}${uuid}`,
                    JSON.stringify(codeInfo), { expirationTtl: duration }
                )
            ]);

            return [true, uuid, maxAmount - newUsed];
        } finally {
            await kvLock.release(kv, key);
        }
    }

    /**
     * 重新认证
     */
    static async authAgain(
        kv: KVNamespace,
        code: string,
        uuid: string,
        binding: string = ""
    ): Promise<AuthResult> {
        const key = `${this.CODE_PREFIX}${await Hash.sha256(code)}`;
        const lock = await kvLock.acquire(kv, key);

        if (!lock) {
            await sleep(randomInt(500, 700));
            return [false, "", 0];
        }

        try {
            // 检查激活码是否被使用过
            const usedStr = await kv.get(key);
            if (!usedStr) {
                await sleep(randomInt(400, 700));
                return [false, "", 0];
            }

            // 获取认证信息
            const ciStr = await kv.get(`${this.CODE_INFO_PREFIX}${uuid}`);
            if (!ciStr) {
                await sleep(randomInt(300, 700));
                return [false, "", 0];
            }

            const codeInfo = JSON.parse(ciStr) as ICodeInfo;
            const bindingHash = await Hash.sha256(binding + key);

            // 验证认证信息
            if (
                codeInfo.uuid !== uuid ||
                codeInfo.binding !== bindingHash ||
                codeInfo.expirationTime <= serverT.now()
            ) {
                return [false, "", 0];
            }

            // 计算剩余次数
            const used = parseInt(usedStr, 10);
            const remaining = codeInfo.amount - used;

            return [true, codeInfo.expirationTime.toString(), remaining];
        } catch {
            return [false, "", 0];
        } finally {
            await kvLock.release(kv, key);
        }
    }
}