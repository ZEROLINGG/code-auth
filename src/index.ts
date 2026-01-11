import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import api from "./routes/api";
import superAdmin from "./routes/superAdmin";




// 指定 Worker 绑定类型
const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use("*", async (c, next) => {
  if (!c.env.SERVER_KEY || !c.env.SUPER_ADMIN_IP || !c.env.SUPER_ADMIN_KEY) {
    return c.text("Server configuration error", 500);
  }

  await next();
});
app.use('*', cors({
  origin: [
    'https://808050.com',
    'http://127.0.0.1',
    'http://tauri.localhost',
  ],
  credentials: true,
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'X-Authorization-A'],
}));
app.use('*', secureHeaders({
  xContentTypeOptions: 'nosniff', // 防止浏览器嗅探 MIME 类型
  xFrameOptions: 'DENY',          // 禁止被嵌入 iframe (防点击劫持)
  xXssProtection: '1; mode=block',// 启用 XSS 过滤
  referrerPolicy: 'strict-origin-when-cross-origin', // 限制 Referer 泄露
}));



app.route("/api/", api);
app.route("/admin/su/", superAdmin);


export default app;
