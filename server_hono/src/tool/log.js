// server_hono/src/tool/log.ts
/**
 * Cloudflare Workers + Queue + D1 日志模块
 * 支持异步队列批量写入 + 结构化查询
 *
 * 使用方式：
 * 1. 在 wrangler.toml 配置 Queue Consumer
 * 2. 在应用入口调用 initLog(env)
 * 3. 使用 log.d/i/w/e/query 方法
 */
export var LogLevel;
(function (LogLevel) {
    LogLevel["DEBUG"] = "DEBUG";
    LogLevel["INFO"] = "INFO";
    LogLevel["WARN"] = "WARN";
    LogLevel["ERROR"] = "ERROR";
})(LogLevel || (LogLevel = {}));
// ====================== 全局实例 ======================
let logger = null;
/**
 * 在 Hono 中间件或入口处初始化
 */
export async function initLog(db, queue) {
    const env = { AUTH_DB: db, LOG_QUEUE: queue };
    if (!logger) {
        logger = new Logger(env);
    }
    await logger.init(); // 提前初始化，不等到第一条日志
}
// ====================== 内部 Logger ======================
class Logger {
    env;
    db;
    queue;
    initialized = false;
    initPromise = null;
    // 配置选项
    config = {
        enableConsole: true, // 同时输出到 console
        enableQueue: true, // 启用队列（可用于测试时禁用）
        fallbackToDirect: true, // 队列失败时直接写入 D1
        maxRetries: 2, // 最大重试次数
    };
    constructor(env) {
        this.env = env;
        this.db = env.AUTH_DB;
        this.queue = env.LOG_QUEUE;
    }
    /**
     * 初始化数据库表（防止竞态条件）
     */
    async init() {
        if (this.initialized)
            return;
        if (this.initPromise)
            return await this.initPromise;
        this.initPromise = (async () => {
            try {
                // 用 prepare().run() 替代 exec()
                await this.db.prepare(`
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            `).run();
                await this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level)`).run();
                await this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(created_at DESC)`).run();
                await this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_tag ON logs(tag)`).run();
                await this.db.prepare(`CREATE INDEX IF NOT EXISTS idx_logs_level_time ON logs(level, created_at DESC)`).run();
                this.initialized = true;
            }
            catch (error) {
                console.error('[Logger] Database initialization failed:', error);
                this.initPromise = null;
                throw error;
            }
        })();
        return this.initPromise;
    }
    /**
     * 发送日志到队列（带降级处理）
     */
    async enqueue(level, tag, message) {
        // Console 输出（开发调试）
        if (this.config.enableConsole) {
            this.logToConsole(level, tag, message);
        }
        // 如果队列被禁用，直接写入
        if (!this.config.enableQueue) {
            return this.writeToDB(level, tag, message, Date.now());
        }
        const queueMessage = {
            level,
            tag,
            message,
            created_at: Date.now(),
        };
        // 尝试发送到队列
        let lastError;
        for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
            try {
                await this.queue.send(queueMessage);
                return; // 成功发送
            }
            catch (error) {
                lastError = error;
                console.error(`[Logger] Queue send failed (attempt ${attempt + 1}):`, error);
                // 最后一次尝试失败后，降级处理
                if (attempt === this.config.maxRetries) {
                    if (this.config.fallbackToDirect) {
                        console.warn('[Logger] Falling back to direct D1 write');
                        try {
                            await this.writeToDB(level, tag, message, queueMessage.created_at);
                            return;
                        }
                        catch (dbError) {
                            console.error('[Logger] Direct D1 write also failed:', dbError);
                        }
                    }
                }
                // 短暂延迟后重试
                if (attempt < this.config.maxRetries) {
                    await new Promise(resolve => setTimeout(resolve, 100 * (attempt + 1)));
                }
            }
        }
        // 所有尝试都失败，仅记录到 console
        console.error('[Logger] All write attempts failed:', lastError);
    }
    /**
     * 直接写入 D1（降级方案）
     */
    async writeToDB(level, tag, message, timestamp) {
        try {
            await this.init();
            await this.db
                .prepare('INSERT INTO logs (level, tag, message, created_at) VALUES (?, ?, ?, ?)')
                .bind(level, tag, message, timestamp)
                .run();
        }
        catch (error) {
            console.error('[Logger] Direct DB write failed:', error);
            throw error;
        }
    }
    /**
     * 输出到控制台
     */
    logToConsole(level, tag, message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] [${level}] [${tag}] ${message}`;
        switch (level) {
            case LogLevel.DEBUG:
                console.debug(logMessage);
                break;
            case LogLevel.INFO:
                console.log(logMessage);
                break;
            case LogLevel.WARN:
                console.warn(logMessage);
                break;
            case LogLevel.ERROR:
                console.error(logMessage);
                break;
        }
    }
    // ==================== 内部日志方法 ====================
    async d(tag, msg) {
        try {
            await this.init();
            await this.enqueue(LogLevel.DEBUG, tag, msg);
        }
        catch (error) {
            console.error('[Logger.d] Failed:', error);
        }
    }
    async i(tag, msg) {
        try {
            await this.init();
            await this.enqueue(LogLevel.INFO, tag, msg);
        }
        catch (error) {
            console.error('[Logger.i] Failed:', error);
        }
    }
    async w(tag, msg) {
        try {
            await this.init();
            await this.enqueue(LogLevel.WARN, tag, msg);
        }
        catch (error) {
            console.error('[Logger.w] Failed:', error);
        }
    }
    async e(tag, msg) {
        try {
            await this.init();
            await this.enqueue(LogLevel.ERROR, tag, msg);
        }
        catch (error) {
            console.error('[Logger.e] Failed:', error);
        }
    }
    async query(levels = [], limit = 100) {
        try {
            await this.init();
            let sql = 'SELECT id, level, message, tag, created_at FROM logs';
            const params = [];
            if (levels.length > 0) {
                const placeholders = levels.map(() => '?').join(',');
                sql += ` WHERE level IN (${placeholders})`;
                params.push(...levels);
            }
            sql += ' ORDER BY created_at DESC, id DESC LIMIT ?';
            params.push(Math.min(limit, 500));
            const { results } = await this.db.prepare(sql).bind(...params).all();
            return results || [];
        }
        catch (error) {
            console.error('[Logger.query] Failed:', error);
            return [];
        }
    }
    /**
     * 清理过期日志
     * @param daysToKeep 保留天数（默认 30 天）
     */
    async cleanup(daysToKeep = 30) {
        try {
            await this.init();
            const cutoffTime = Date.now() - daysToKeep * 24 * 60 * 60 * 1000;
            const result = await this.db
                .prepare('DELETE FROM logs WHERE created_at < ?')
                .bind(cutoffTime)
                .run();
            const deletedCount = result.meta.changes || 0;
            console.log(`[Logger] Cleaned up ${deletedCount} old log entries`);
            return deletedCount;
        }
        catch (error) {
            console.error('[Logger.cleanup] Failed:', error);
            return 0;
        }
    }
}
// ====================== 对外统一接口 ======================
export class log {
    static d(tag, msg) {
        if (!logger) {
            console.debug(`[${tag}] ${msg}`);
            return;
        }
        logger.d(tag, msg).then(() => { });
    }
    static i(tag, msg) {
        if (!logger) {
            console.log(`[${tag}] ${msg}`);
            return;
        }
        logger.i(tag, msg).then(() => { });
    }
    static w(tag, msg) {
        if (!logger) {
            console.warn(`[${tag}] ${msg}`);
            return;
        }
        logger.w(tag, msg).then(() => { });
    }
    static e(tag, msg) {
        if (!logger) {
            console.error(`[${tag}] ${msg}`);
            if (msg instanceof Error)
                console.error(msg.stack);
            return;
        }
        const message = msg instanceof Error ? msg.message : msg;
        logger.e(tag, message).then(() => { });
        // 记录堆栈信息
        if (msg instanceof Error && msg.stack) {
            logger.e(tag, `Stack: ${msg.stack}`).then(() => { });
        }
    }
    static async query(levels = [], limit = 100) {
        if (!logger) {
            console.error('[Log] 未初始化，无法查询');
            return [];
        }
        return logger.query(levels, limit);
    }
    /**
     * 清理过期日志
     */
    static async cleanup(daysToKeep = 30) {
        if (!logger) {
            console.error('[Log] 未初始化，无法清理');
            return 0;
        }
        return logger.cleanup(daysToKeep);
    }
}
// ====================== Queue Consumer ======================
/**
 * Queue Consumer Handler
 * 需要在 wrangler.toml 中配置此函数为 queue consumer
 */
export async function handleLogQueue(batch, env) {
    console.log(`[LogQueue] Processing ${batch.messages.length} messages`);
    try {
        // 批量插入准备
        const stmt = env.AUTH_DB.prepare('INSERT INTO logs (level, tag, message, created_at) VALUES (?, ?, ?, ?)');
        const insertions = batch.messages.map(msg => {
            const { level, tag, message, created_at } = msg.body;
            return stmt.bind(level, tag, message, created_at);
        });
        // 批量执行
        const results = await env.AUTH_DB.batch(insertions);
        // 检查失败的记录
        const failedCount = results.filter(r => !r.success).length;
        if (failedCount > 0) {
            console.error(`[LogQueue] ${failedCount} insertions failed`);
        }
        else {
            console.log(`[LogQueue] Successfully inserted ${batch.messages.length} logs`);
        }
        // 重试失败的消息
        for (let i = 0; i < batch.messages.length; i++) {
            if (!results[i].success) {
                const msg = batch.messages[i];
                console.error(`[LogQueue] Failed to insert:`, msg.body);
                msg.retry(); // 标记为需要重试
            }
            else {
                batch.messages[i].ack(); // 确认成功
            }
        }
    }
    catch (error) {
        console.error('[LogQueue] Batch processing failed:', error);
        // 批量失败，重试所有消息
        batch.messages.forEach(msg => msg.retry());
        throw error;
    }
}
