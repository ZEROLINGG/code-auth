import {randomString, kvLock} from "./tool";

interface IProduct {
    name: string;
    id: string;
}

const UNSAFE_CHAR_REGEX = /[^\u4e00-\u9fa5a-zA-Z0-9._=\[\]()*#@!+$\-]/g;
function normalizeString(raw: string): string {
    if (!raw) return "";
    let name = raw.length > 50 ? raw.slice(0, 50) : raw;
    name = name.replace(UNSAFE_CHAR_REGEX, "").trim();
    if (name.length === 0 || name.length > 50) {
        return "";
    }
    return name;
}

export class Product {
    // KV 键前缀
    private static readonly PREFIX_NAME = "P:N:";   // P:N:<name> -> id
    private static readonly PREFIX_ID = "P:I:";     // P:I:<id>   -> name
    private static readonly ALL_NAMES_KEY = "P:A";  // P:A        -> [name1, name2, ...]
    private static readonly PRODUCT_ID_LENGTH = 7;

    /**
     * 添加产品
     * 写入 3 个 key：名称索引、ID索引、名称列表
     */
    static async set(kv: KVNamespace, name: string): Promise<[boolean, string]> {
        name = normalizeString(name);
        if (!name) return [false, ""];

        const nameKey = `${this.PREFIX_NAME}${name}`;

        await kvLock.waitAndAcquire(kv, nameKey);
        try {
            // O(1) 检查名称是否已存在
            const existingId = await kv.get(nameKey);
            if (existingId) {
                return [false, ""];
            }

            const id = randomString(this.PRODUCT_ID_LENGTH);
            const allNames = await this.getNames(kv);
            allNames.push(name);

            // 并行写入三个 key
            await Promise.all([
                kv.put(nameKey, id),
                kv.put(`${this.PREFIX_ID}${id}`, name),
                kv.put(this.ALL_NAMES_KEY, JSON.stringify(allNames))
            ]);

            return [true, id];
        } finally {
            await kvLock.release(kv, nameKey);
        }
    }

    /**
     * 通过名称获取产品 ID
     */
    static async getId(kv: KVNamespace, name: string): Promise<[boolean, string]> {
        name = normalizeString(name);
        if (!name) return [false, ""];

        const id = await kv.get(`${this.PREFIX_NAME}${name}`);
        return id ? [true, id] : [false, ""];
    }

    /**
     * 通过 ID 获取产品名称
     */
    static async getName(kv: KVNamespace, id: string): Promise<[boolean, string]> {
        id = id.trim();
        if (!id) return [false, ""];

        const name = await kv.get(`${this.PREFIX_ID}${id}`);
        return name ? [true, name] : [false, ""];
    }

    /**
     * 获取所有产品名称
     */
    static async getNames(kv: KVNamespace): Promise<string[]> {
        const namesJson = await kv.get(this.ALL_NAMES_KEY);
        if (!namesJson) return [];

        try {
            return JSON.parse(namesJson) as string[];
        } catch {
            return [];
        }
    }

    /**
     * 获取所有产品（完整信息）
     */
    static async gets(kv: KVNamespace): Promise<IProduct[]> {
        const names = await this.getNames(kv);
        if (names.length === 0) return [];

        // 并行批量获取所有 ID
        const ids = await Promise.all(
            names.map(name => kv.get(`${this.PREFIX_NAME}${name}`))
        );

        return names
            .map((name, i) => ({ name, id: ids[i] ?? "" }))
            .filter(p => p.id !== "");
    }

    /**
     * 判断产品名是否存在
     */
    static async existsName(kv: KVNamespace, name: string): Promise<boolean> {
        name = normalizeString(name);
        if (!name) return false;

        return (await kv.get(`${this.PREFIX_NAME}${name}`)) !== null;
    }

    /**
     * 判断产品 ID 是否存在
     */
    static async existsId(kv: KVNamespace, id: string): Promise<boolean> {
        id = id.trim();
        if (!id) return false;

        return (await kv.get(`${this.PREFIX_ID}${id}`)) !== null;
    }

    /**
     * 删除产品
     */
    static async delete(kv: KVNamespace, id: string): Promise<boolean> {
        id = id.trim();
        if (!id) return false;

        const idKey = `${this.PREFIX_ID}${id}`;

        await kvLock.waitAndAcquire(kv, idKey);
        try {
            const name = await kv.get(idKey);
            if (!name) return false;

            const allNames = await this.getNames(kv);
            const newNames = allNames.filter(n => n !== name);

            await Promise.all([
                kv.delete(`${this.PREFIX_NAME}${name}`),
                kv.delete(idKey),
                kv.put(this.ALL_NAMES_KEY, JSON.stringify(newNames))
            ]);

            return true;
        } finally {
            await kvLock.release(kv, idKey);
        }
    }
}