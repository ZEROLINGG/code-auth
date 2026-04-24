import { Hono, Context } from "hono";
import { z } from "zod";
import { getClientIP } from "../tool/tool";
import { log, LogLevel, LogEntry } from "../tool/log";

const TAG = "LOG_API";

// ═══════════════════════════════════════════════════════════
//                       工具函数
// ═══════════════════════════════════════════════════════════

const Logd = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    log.d(TAG, `[${c.req.method} ${c.req.path}][${ip}] ${msg}`);
};
const Logi = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    log.i(TAG, `[${c.req.method} ${c.req.path}][${ip}] ${msg}`);
};
const Logw = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    log.w(TAG, `[${c.req.method} ${c.req.path}][${ip}] ${msg}`);
};
const Loge = (c: Context, msg: string) => {
    const ip = getClientIP(c);
    log.e(TAG, `[${c.req.method} ${c.req.path}][${ip}] ${msg}`);
};

function Ok(c: Context, data?: any, message = "ok"): Response {
    return c.json({ success: true, code: 200, message, data });
}
function Err(c: Context, message = "error", code = 400): Response {
    return c.json({ success: false, code, message });
}

export async function parseJson<T extends z.ZodTypeAny>(
    c: Context,
    schema: T
): Promise<z.infer<T> | null> {
    try {
        const body = await c.req.json();
        const result = schema.safeParse(body);
        if (!result.success) return null;
        return result.data;
    } catch {
        return null;
    }
}

// ═══════════════════════════════════════════════════════════
//                       管理员认证
// ═══════════════════════════════════════════════════════════

async function authSuperAdmin(
    c: Context<{ Bindings: CloudflareBindings }>
): Promise<boolean> {
    const { SUPER_ADMIN_KEY, SUPER_ADMIN_IP } = c.env;
    if (!SUPER_ADMIN_KEY || !SUPER_ADMIN_IP) {
        console.error("Super admin config missing");
        return false;
    }
    const xAuth = c.req.header("X-Authorization-A") || "";
    if (xAuth !== SUPER_ADMIN_KEY) {
        console.log("Admin auth failed: invalid key");
        return false;
    }
    const clientIp = getClientIP(c);
    const allowedIPs = SUPER_ADMIN_IP
        .split(/[;,]/)
        .map((ip) => ip.trim())
        .filter((ip) => ip.length > 0);
    if (allowedIPs.length === 0) {
        console.error("SUPER_ADMIN_IP is empty after parsing");
        return false;
    }
    return allowedIPs.includes(clientIp);
}

// ═══════════════════════════════════════════════════════════
//                        API 路由
// ═══════════════════════════════════════════════════════════

const api = new Hono<{ Bindings: CloudflareBindings }>();

/** 全局管理员认证中间件 */
api.use("*", async (c, next) => {
    try {
        if (!await authSuperAdmin(c)) {
            Logw(c, "管理员认证失败");
            return Err(c, "未授权", 401);
        }
        await next();
    } catch (e) {
        Loge(c, `严重服务器错误: ${e}`);
        return Err(c, "严重服务器错误");
    }
});

// ───────────────────────────────────────────────────────────
// GET /admin/log/query
// 查询日志，支持按级别过滤 + 分页
// Body: { levels?: string[], limit?: number }
// ───────────────────────────────────────────────────────────
api.post("/admin/log/query", async (c) => {
    const QueryBody = z.object({
        levels: z
            .array(z.enum(["DEBUG", "INFO", "WARN", "ERROR"]))
            .optional()
            .default([]),
        limit: z.number().int().min(1).max(500).optional().default(100),
    });

    const body = await parseJson(c, QueryBody);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }

    const levels = body.levels as LogLevel[];
    const entries: LogEntry[] = await log.query(levels, body.limit);

    Logd(c, `查询日志成功, 条数: ${entries.length}, 级别过滤: [${levels.join(",")}]`);

    return Ok(c, {
        total: entries.length,
        entries,
    });
});

// ───────────────────────────────────────────────────────────
// POST /admin/log/cleanup
// 清理过期日志
// Body: { days_to_keep?: number }   默认 30 天
// ───────────────────────────────────────────────────────────
api.post("/admin/log/cleanup", async (c) => {
    const CleanupBody = z.object({
        days_to_keep: z.number().int().min(1).max(3650).optional().default(30),
    });

    const body = await parseJson(c, CleanupBody);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }

    const deleted = await log.cleanup(body.days_to_keep);

    Logi(c, `日志清理完成, 删除条数: ${deleted}, 保留天数: ${body.days_to_keep}`);

    return Ok(c, { deleted });
});

// ───────────────────────────────────────────────────────────
// POST /admin/log/stats
// 统计各级别日志数量（最近 N 条内）
// Body: { limit?: number }
// ───────────────────────────────────────────────────────────
api.post("/admin/log/stats", async (c) => {
    const StatsBody = z.object({
        limit: z.number().int().min(1).max(500).optional().default(500),
    });

    const body = await parseJson(c, StatsBody);
    if (!body) {
        Logw(c, "请求格式错误");
        return Err(c, "请求格式错误");
    }

    // 拉取全部级别，在内存里做统计
    const entries: LogEntry[] = await log.query([], body.limit);

    const stats: Record<string, number> = {
        DEBUG: 0,
        INFO: 0,
        WARN: 0,
        ERROR: 0,
    };
    for (const entry of entries) {
        if (entry.level in stats) {
            stats[entry.level]++;
        }
    }

    Logd(c, `日志统计完成, 样本量: ${entries.length}`);

    return Ok(c, {
        sample_size: entries.length,
        stats,
    });
});

export default api;