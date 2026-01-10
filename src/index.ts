import { Hono } from "hono";

// 指定 Worker 绑定类型
const app = new Hono<{ Bindings: CloudflareBindings }>();

app.use("*", async (c, next) => {
  if (!c.env.SERVER_KEY) {
    return c.text("Server configuration error", 500);
  }

  await next();
});


// 测试普通接口
app.get("/message", (c) => {
  return c.text("Hello Hono!");
});

// 写入 KV
app.get("/set/:key/:value", async (c) => {
  const key = c.req.param("key");
  const value = c.req.param("value");

  if (!key || !value) {
    return c.text("Key or value missing", 400);
  }

  await c.env.AUTH_KV.put(key, value);
  return c.text(`Saved ${key}=${value} to KV`);
});

// 从 KV 读取
app.get("/get/:key", async (c) => {
  const key = c.req.param("key");

  if (!key) {
    return c.text("Key missing", 400);
  }

  const value = await c.env.AUTH_KV.get(key);
  if (value === null) {
    return c.text(`${key} not found`, 404);
  }

  return c.text(`Value for ${key}: ${value}`);
});

export default app;
