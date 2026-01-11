// routes/superAdmin.ts
import {Context, Hono} from "hono";
import { Product, Code } from "../tool/code";
import {getClientIP} from "../tool/tool";
import suHtml from '../html/superAdminPage.html';

const superAdmin = new Hono<{ Bindings: CloudflareBindings }>();


async function authSuperAdmin(
    c: Context<{ Bindings: CloudflareBindings }>
): Promise<boolean> {

    const { SUPER_ADMIN_KEY, SUPER_ADMIN_IP } = c.env;

    if (!SUPER_ADMIN_KEY || !SUPER_ADMIN_IP) {
        console.error("Super admin config missing");
        return false;
    }

    // 1. 校验 Admin Key
    const xAuth = c.req.header("X-Authorization-A") || "";
    if (xAuth !== SUPER_ADMIN_KEY) {
        console.log("Admin auth failed: invalid key");
        return false;
    }

    // 2. IP 白名单校验（支持 , 和 ;）
    const clientIp = getClientIP(c.req.raw);

    const allowedIPs = SUPER_ADMIN_IP
        .split(/[;,]/)          // 同时支持 , ;
        .map(ip => ip.trim())
        .filter(ip => ip.length > 0);

    // 防御性校验：配置异常直接拒绝
    if (allowedIPs.length === 0) {
        console.error("SUPER_ADMIN_IP is empty after parsing");
        return false;
    }

    return allowedIPs.includes(clientIp);
}


/**
 * 获取所有产品列表
 * GET /super/products
 */
superAdmin.get("/products", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const products = await Product.gets(c.env.AUTH_KV);
        return c.json({
            success: true,
            data: products,
            count: products.length
        });
    } catch (error) {
        console.error("Get products error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 添加新产品
 * POST /super/product
 * Body: { "name": "产品名称" }
 */
superAdmin.post("/product", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const body = await c.req.json();
        const { name } = body;

        if (!name || typeof name !== "string") {
            return c.json({ success: false, message: "Invalid product name" }, 400);
        }

        const [success, productId] = await Product.set(c.env.AUTH_KV, name);

        if (!success) {
            return c.json({
                success: false,
                message: "Product already exists or invalid name"
            }, 400);
        }

        return c.json({
            success: true,
            message: "Product created successfully",
            data: { name, id: productId }
        });
    } catch (error) {
        console.error("Create product error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 检查产品名是否存在
 * GET /super/product/check/:name
 */
superAdmin.get("/product/check/:name", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const name = c.req.param("name");
        const exists = await Product.existsName(c.env.AUTH_KV, name);

        return c.json({
            success: true,
            exists,
            name
        });
    } catch (error) {
        console.error("Check product error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 根据产品名生成激活码
 * POST /super/code/generate
 * Body: {
 *   "productName": "产品名称",
 *   "expirationPeriod": 2592000,    // 激活码有效期（秒），如 30天
 *   "activationDuration": 31536000, // 激活后的使用时长（秒），如 1年
 *   "amount": 1                     // 可使用次数
 * }
 */
superAdmin.post("/code/generate", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const body = await c.req.json();
        const { productName, expirationPeriod, activationDuration, amount } = body;

        // 参数验证
        if (!productName || typeof productName !== "string") {
            return c.json({ success: false, message: "Invalid productName" }, 400);
        }

        if (typeof expirationPeriod !== "number" || expirationPeriod <= 0) {
            return c.json({ success: false, message: "Invalid expirationPeriod" }, 400);
        }

        if (typeof activationDuration !== "number" || activationDuration <= 0) {
            return c.json({ success: false, message: "Invalid activationDuration" }, 400);
        }

        if (typeof amount !== "number" || amount <= 0 || !Number.isInteger(amount)) {
            return c.json({ success: false, message: "Invalid amount" }, 400);
        }

        const [success, code] = await Code.gent(
            c.env.AUTH_KV,
            c.env.SERVER_KEY,
            productName,
            expirationPeriod,
            activationDuration,
            amount
        );

        if (!success) {
            return c.json({
                success: false,
                message: "Product not found or code generation failed"
            }, 400);
        }

        return c.json({
            success: true,
            message: "Activation code generated successfully",
            data: {
                code,
                productName,
                expirationPeriod,
                activationDuration,
                amount
            }
        });
    } catch (error) {
        console.error("Generate code error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 根据产品ID生成激活码
 * POST /super/code/generate-by-id
 * Body: {
 *   "productId": "产品ID",
 *   "expirationPeriod": 2592000,
 *   "activationDuration": 31536000,
 *   "amount": 1
 * }
 */
superAdmin.post("/code/generate-by-id", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const body = await c.req.json();
        const { productId, expirationPeriod, activationDuration, amount } = body;

        // 参数验证
        if (!productId || typeof productId !== "string") {
            return c.json({ success: false, message: "Invalid productId" }, 400);
        }

        if (typeof expirationPeriod !== "number" || expirationPeriod <= 0) {
            return c.json({ success: false, message: "Invalid expirationPeriod" }, 400);
        }

        if (typeof activationDuration !== "number" || activationDuration <= 0) {
            return c.json({ success: false, message: "Invalid activationDuration" }, 400);
        }

        if (typeof amount !== "number" || amount <= 0 || !Number.isInteger(amount)) {
            return c.json({ success: false, message: "Invalid amount" }, 400);
        }

        const [success, code] = await Code.gentId(
            c.env.AUTH_KV,
            c.env.SERVER_KEY,
            productId,
            expirationPeriod,
            activationDuration,
            amount
        );

        if (!success) {
            return c.json({
                success: false,
                message: "Product not found or code generation failed"
            }, 400);
        }

        return c.json({
            success: true,
            message: "Activation code generated successfully",
            data: {
                code,
                productId,
                expirationPeriod,
                activationDuration,
                amount
            }
        });
    } catch (error) {
        console.error("Generate code by id error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 批量生成激活码
 * POST /super/code/batch-generate
 * Body: {
 *   "productName": "产品名称",
 *   "expirationPeriod": 2592000,
 *   "activationDuration": 31536000,
 *   "amount": 1,
 *   "count": 10  // 生成数量
 * }
 */
superAdmin.post("/code/batch-generate", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.json({ success: false, message: "Unauthorized" }, 401);
        }

        const body = await c.req.json();
        const { productName, expirationPeriod, activationDuration, amount, count } = body;

        // 参数验证
        if (!productName || typeof productName !== "string") {
            return c.json({ success: false, message: "Invalid productName" }, 400);
        }

        if (typeof expirationPeriod !== "number" || expirationPeriod <= 0) {
            return c.json({ success: false, message: "Invalid expirationPeriod" }, 400);
        }

        if (typeof activationDuration !== "number" || activationDuration <= 0) {
            return c.json({ success: false, message: "Invalid activationDuration" }, 400);
        }

        if (typeof amount !== "number" || amount <= 0 || !Number.isInteger(amount)) {
            return c.json({ success: false, message: "Invalid amount" }, 400);
        }

        if (typeof count !== "number" || count <= 0 || count > 100 || !Number.isInteger(count)) {
            return c.json({
                success: false,
                message: "Invalid count (must be 1-100)"
            }, 400);
        }

        // 批量生成
        const codes: string[] = [];
        for (let i = 0; i < count; i++) {
            const [success, code] = await Code.gent(
                c.env.AUTH_KV,
                c.env.SERVER_KEY,
                productName,
                expirationPeriod,
                activationDuration,
                amount
            );

            if (!success) {
                return c.json({
                    success: false,
                    message: `Failed to generate code ${i + 1}`
                }, 500);
            }

            codes.push(code);
        }

        return c.json({
            success: true,
            message: `Successfully generated ${count} activation codes`,
            data: {
                codes,
                productName,
                count,
                expirationPeriod,
                activationDuration,
                amount
            }
        });
    } catch (error) {
        console.error("Batch generate codes error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

superAdmin.get("/", async (c) => {
    return c.html(suHtml);
});

export default superAdmin;