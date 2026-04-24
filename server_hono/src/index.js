import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import api from "./routes/api";
import superAdmin, { authSuperAdmin } from "./routes/superAdmin";
import init from "./tool/pkg/wasm.js";
import wasm from "./tool/pkg/wasm_bg.wasm";
import { handleLogQueue, initLog } from "./tool/log";
// 指定 Worker 绑定类型
const app = new Hono();
let wasmReady = null;
function initWasm() {
    if (!wasmReady) {
        wasmReady = (async () => {
            await init(wasm);
        })();
    }
    return wasmReady;
}
app.use("*", async (c, next) => {
    if (!c.env.SERVER_KEY || !c.env.SUPER_ADMIN_IP || !c.env.SUPER_ADMIN_KEY) {
        return c.text("Server configuration error", 500);
    }
    await initWasm();
    await initLog(c.env.AUTH_DB, c.env.LOG_QUEUE);
    await next();
});
app.use('*', cors({
    origin: [
        'https://808050.com',
        'http://127.0.0.1',
        'http://localhost:1420',
        'http://tauri.localhost',
        'http://127.0.0.1:8000'
    ],
    credentials: true,
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'X-Authorization-A', 'Service'],
}));
app.use('*', secureHeaders({
    xContentTypeOptions: 'nosniff', // 防止浏览器嗅探 MIME 类型
    xFrameOptions: 'DENY', // 禁止被嵌入 iframe (防点击劫持)
    xXssProtection: '1; mode=block', // 启用 XSS 过滤
    referrerPolicy: 'strict-origin-when-cross-origin', // 限制 Referer 泄露
}));
app.get("/", async (c) => {
    if (await authSuperAdmin(c))
        return c.redirect("/admin/su/", 302);
    return c.text("Not Found", 404);
});
app.route("/api/", api);
app.route("/admin/su/", superAdmin);
app.get("*", async (c) => {
    return c.text("Not Found", 404);
});
app.post("*", async (c) => {
    return c.text("Not Found", 404);
});
export default {
    fetch: app.fetch.bind(app),
    async queue(batch, env) {
        await handleLogQueue(batch, env);
    }
};
