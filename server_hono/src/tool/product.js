//server_hono/src/tool/product.ts
import { kvLock } from "./tool";
import { random_u32 } from "./tool";
import { random_bytes } from "./tool";
const UNSAFE_CHAR_REGEX = /[^\u4e00-\u9fa5a-zA-Z0-9._=\[\]()*#@!+$\-]/g;
function normalizeString(raw) {
    if (!raw)
        return "";
    let name = raw.length > 50 ? raw.slice(0, 50) : raw;
    name = name.replace(UNSAFE_CHAR_REGEX, "").trim();
    if (name.length === 0 || name.length > 50) {
        return "";
    }
    return name;
}
/** u32 number -> 8位十六进制字符串，用于 KV key */
function u32ToHex(id) {
    return (id >>> 0).toString(16).padStart(8, "0");
}
/** 8位十六进制字符串 -> u32 number */
function hexToU32(hex) {
    if (!/^[0-9a-f]{8}$/i.test(hex))
        return null;
    const n = parseInt(hex, 16);
    return isNaN(n) ? null : n >>> 0;
}
/** Uint8Array -> base64 string */
function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
/** base64 string -> Uint8Array */
function base64ToBytes(base64) {
    try {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    catch {
        return null;
    }
}
export class Product {
    static PREFIX_NAME = "P:N:"; // P:N:<name>      -> hex(id)
    static PREFIX_ID = "P:I:"; // P:I:<hex_id>    -> name
    static PREFIX_KEY = "P:K:"; // P:K:<hex_id>    -> base64(key)
    static ALL_NAMES_KEY = "P:A"; // P:A             -> Set<string>
    static KEY_LENGTH = 32; // 产品密钥长度 32 字节
    /**
     * 将 Set<string> 序列化为 JSON 字符串
     * Set 自动去重，保证数据一致性
     */
    static serializeSet(set) {
        return JSON.stringify([...set]);
    }
    /**
     * 将 JSON 字符串反序列化为 Set<string>
     */
    static deserializeSet(json) {
        if (!json)
            return new Set();
        try {
            const arr = JSON.parse(json);
            if (!Array.isArray(arr))
                return new Set();
            return new Set(arr.filter((v) => typeof v === "string"));
        }
        catch {
            return new Set();
        }
    }
    /** 生成唯一 u32 id，避免碰撞 */
    static async generateUniqueId(kv) {
        while (true) {
            const id = random_u32();
            const exists = await kv.get(`${this.PREFIX_ID}${u32ToHex(id)}`);
            if (!exists)
                return id;
        }
    }
    /**
     * 生成产品密钥 [u8, 32]
     */
    static generateKey() {
        return random_bytes(this.KEY_LENGTH);
    }
    /**
     * 添加产品
     * 锁定顺序：ALL_NAMES_LOCK -> nameKey
     * 返回 [成功, product_id(u32)]，失败时 id 为 0
     */
    static async set(kv, name) {
        name = normalizeString(name);
        if (!name)
            return [false, 0];
        const nameKey = `${this.PREFIX_NAME}${name}`;
        // 先锁定 ALL_NAMES
        await kvLock.waitAndAcquire(kv, this.ALL_NAMES_KEY);
        try {
            // 再锁定具体的 nameKey
            await kvLock.waitAndAcquire(kv, nameKey);
            try {
                // O(1) 检查名称是否已存在
                const existingId = await kv.get(nameKey);
                if (existingId) {
                    return [false, 0];
                }
                const id = await this.generateUniqueId(kv);
                const idHex = u32ToHex(id);
                // 生成产品密钥
                const keyBytes = this.generateKey();
                if (!keyBytes) {
                    return [false, 0];
                }
                const keyBase64 = bytesToBase64(keyBytes);
                // 使用 Set 添加名称
                const allNamesSet = await this.getNamesSet(kv);
                allNamesSet.add(name);
                await Promise.all([
                    kv.put(nameKey, idHex),
                    kv.put(`${this.PREFIX_ID}${idHex}`, name),
                    kv.put(`${this.PREFIX_KEY}${idHex}`, keyBase64),
                    kv.put(this.ALL_NAMES_KEY, this.serializeSet(allNamesSet))
                ]);
                return [true, id];
            }
            finally {
                await kvLock.release(kv, nameKey);
            }
        }
        finally {
            await kvLock.release(kv, this.ALL_NAMES_KEY);
        }
    }
    /**
     * 通过名称获取产品 ID (u32)
     */
    static async getId(kv, name) {
        name = normalizeString(name);
        if (!name)
            return [false, 0];
        const idHex = await kv.get(`${this.PREFIX_NAME}${name}`);
        if (!idHex)
            return [false, 0];
        const id = hexToU32(idHex);
        return id !== null ? [true, id] : [false, 0];
    }
    /**
     * 通过 ID (u32) 获取产品名称
     */
    static async getName(kv, id) {
        const idHex = u32ToHex(id);
        const name = await kv.get(`${this.PREFIX_ID}${idHex}`);
        return name ? [true, name] : [false, ""];
    }
    /**
     * 通过 ID (u32) 获取产品密钥 [u8, 32]
     * 返回 [成功, Uint8Array | null]，失败时返回 null
     */
    static async getKey(kv, id) {
        const idHex = u32ToHex(id);
        const keyBase64 = await kv.get(`${this.PREFIX_KEY}${idHex}`);
        if (!keyBase64) {
            return [false, null];
        }
        const keyBytes = base64ToBytes(keyBase64);
        if (!keyBytes || keyBytes.length !== this.KEY_LENGTH) {
            return [false, null];
        }
        return [true, keyBytes];
    }
    /**
     * 获取所有产品名称 Set
     * 内部方法，用于高效操作
     */
    static async getNamesSet(kv) {
        const namesJson = await kv.get(this.ALL_NAMES_KEY);
        return this.deserializeSet(namesJson);
    }
    /**
     * 获取所有产品名称（读操作，无锁）
     * 返回数组，保持原有接口不变
     */
    static async getNames(kv) {
        const set = await this.getNamesSet(kv);
        return [...set];
    }
    /**
     * 获取所有产品（完整信息）
     */
    static async gets(kv) {
        const names = await this.getNames(kv);
        if (names.length === 0)
            return [];
        const idHexList = await Promise.all(names.map(name => kv.get(`${this.PREFIX_NAME}${name}`)));
        return names
            .map((name, i) => {
            const hex = idHexList[i];
            if (!hex)
                return null;
            const id = hexToU32(hex);
            if (id === null)
                return null;
            return { name, id };
        })
            .filter((p) => p !== null);
    }
    /**
     * 判断产品名是否存在
     */
    static async existsName(kv, name) {
        name = normalizeString(name);
        if (!name)
            return false;
        return (await kv.get(`${this.PREFIX_NAME}${name}`)) !== null;
    }
    /**
     * 判断产品 ID (u32) 是否存在
     */
    static async existsId(kv, id) {
        return (await kv.get(`${this.PREFIX_ID}${u32ToHex(id)}`)) !== null;
    }
    /**
     * 删除产品（通过 u32 id）
     * 锁定顺序：ALL_NAMES_LOCK -> idKey
     */
    static async delete(kv, id) {
        const idHex = u32ToHex(id);
        const idKey = `${this.PREFIX_ID}${idHex}`;
        // 先锁定 ALL_NAMES
        await kvLock.waitAndAcquire(kv, this.ALL_NAMES_KEY);
        try {
            // 再锁定具体的 idKey
            await kvLock.waitAndAcquire(kv, idKey);
            try {
                const name = await kv.get(idKey);
                if (!name)
                    return false;
                // 使用 Set 删除名称
                const allNamesSet = await this.getNamesSet(kv);
                allNamesSet.delete(name);
                await Promise.all([
                    kv.delete(`${this.PREFIX_NAME}${name}`),
                    kv.delete(idKey),
                    kv.delete(`${this.PREFIX_KEY}${idHex}`),
                    kv.put(this.ALL_NAMES_KEY, this.serializeSet(allNamesSet))
                ]);
                return true;
            }
            finally {
                await kvLock.release(kv, idKey);
            }
        }
        finally {
            await kvLock.release(kv, this.ALL_NAMES_KEY);
        }
    }
}
