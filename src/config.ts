// 配置常量
export const CONFIG = {
    RSA_KEY_UPDATE_TIME: 60 * 60 * 24,     // 24小时
    CLIENT_KEY_TTL: 300,                     // 客户端Key存活时间
    TIMESTAMP_TOLERANCE_MS: 60 * 1000,       // 时间戳容差
    MAX_QUANTITY: 100,                       // 单次最大生成数量
    MAX_VALIDITY_SECONDS: 365 * 24 * 60 * 60, // 最大有效期1年


    ServerBaseTimestamp: 1766000000
} as const;
