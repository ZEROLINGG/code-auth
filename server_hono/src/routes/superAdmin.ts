// routes/superAdmin.ts
import {Context, Hono} from "hono";
// import { Code } from "../tool/code";
import {base64_encode_from_str, code_v1_generate} from "../tool/pkg";
import {getClientIP} from "../tool/tool";
import suHtml from '../html/superAdminPage.html';
import {Product} from "../tool/product";

import {log} from "../tool/log";

const TAG = "ADMIN_API";
//
// const Logd = (c: Context, msg: string) => {
//     const ip = getClientIP(c);
//     const path = c.req.path;
//     const method = c.req.method;
//     log.d(TAG, `[${method} ${path}][${ip}] ${msg}`);
// };
//
// const Logi = (c: Context, msg: string) => {
//     const ip = getClientIP(c);
//     const path = c.req.path;
//     const method = c.req.method;
//     log.i(TAG, `[${method} ${path}][${ip}] ${msg}`);
// };
// const Logw = (c: Context, msg: string) => {
//     const ip = getClientIP(c);
//     const path = c.req.path;
//     const method = c.req.method;
//     log.w(TAG, `[${method} ${path}][${ip}] ${msg}`);
// };
// const Loge = (c: Context, msg: string) => {
//     const ip = getClientIP(c);
//     const path = c.req.path;
//     const method = c.req.method;
//     log.e(TAG, `[${method} ${path}][${ip}] ${msg}`);
// };

const superAdmin = new Hono<{ Bindings: CloudflareBindings }>();


export async function authSuperAdmin(
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
    const clientIp = getClientIP(c);

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
 * GET /products
 */
superAdmin.get("/products", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.text("Not Found", 404);
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
 * POST /product
 * Body: { "name": "产品名称" }
 */
superAdmin.post("/product", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.text("Not Found", 404);
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
 * GET /product/check/:name
 */
superAdmin.get("/product/check/:name", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.text("Not Found", 404);
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
 * 删除产品
 * DELETE /product/:id
 */
superAdmin.delete("/product/:id", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);
        if (!isAuthed) {
            return c.text("Not Found", 404);
        }

        // 从 URL 中获取产品 ID
        const id = c.req.param("id");
        if (!id) {
            return c.json({ success: false, message: "Product ID is required" }, 400);
        }

        // 调用 Product 类的 delete 方法
        const success = await Product.delete(c.env.AUTH_KV, Number(id));

        if (!success) {
            // 如果删除失败，很可能是因为该 ID 不存在
            return c.json({
                success: false,
                message: "Product not found or failed to delete"
            }, 404);
        }

        return c.json({
            success: true,
            message: "Product deleted successfully"
        });

    } catch (error) {
        console.error("Delete product error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 根据产品ID生成单个激活码
 * POST /code/generate-by-id
 * Body: {
 *   "productId": number,
 *   "codeValidDuration": number,     // 激活码有效期（秒），从生成时刻开始计算
 *   "useMaxDuration": number,       // 最大使用时长（秒），激活后可用时间
 *   "maxUses": number,              // 最大使用次数
 *   "prebind"?: number | null       // 预绑定用户ID（可选）
 * }
 */
superAdmin.post("/code/generate-by-id", async (c) => {
    try {
        // 超级管理员认证
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.text("Not Found", 404);
        }

        const body = await c.req.json();
        const { productId, codeValidDuration, useMaxDuration, maxUses, prebind } = body;

        // 1. 参数验证
        if (!productId || typeof productId !== "number" || !Number.isInteger(productId)) {
            return c.json({ success: false, message: "Invalid productId" }, 400);
        }

        if (typeof codeValidDuration !== "number" || codeValidDuration <= 0 || !Number.isInteger(codeValidDuration)) {
            return c.json({ success: false, message: "Invalid codeValidDuration" }, 400);
        }

        if (typeof useMaxDuration !== "number" || useMaxDuration <= 0 || !Number.isInteger(useMaxDuration)) {
            return c.json({ success: false, message: "Invalid useMaxDuration" }, 400);
        }

        if (typeof maxUses !== "number" || maxUses <= 0 || !Number.isInteger(maxUses)) {
            return c.json({ success: false, message: "Invalid maxUses" }, 400);
        }

        // prebind 可选，但如果有值必须是有效的整数
        if (prebind !== undefined && prebind !== null) {
            if (typeof prebind !== "number" || !Number.isInteger(prebind)) {
                return c.json({ success: false, message: "Invalid prebind" }, 400);
            }
        }

        // 2. 检查产品是否存在
        if (!await Product.existsId(c.env.AUTH_KV, productId)) {
            return c.json({ success: false, message: "Product not found" }, 404);
        }

        // 3. 获取产品密钥
        const [ok, productKey] = await Product.getKey(c.env.AUTH_KV, productId);

        if (!ok || !productKey) {
            return c.json({ success: false, message: "Failed to get product key" }, 500);
        }

        // 4. 生成激活码
        const code = code_v1_generate(
            productKey,
            productId,
            codeValidDuration,
            useMaxDuration,
            maxUses,
            prebind ?? null
        );

        if (!code) {
            return c.json({ success: false, message: "Code generation failed" }, 500);
        }

        return c.json({
            success: true,
            message: "Activation code generated successfully",
            data: {
                code,
                productId,
                codeValidDuration,
                useMaxDuration,
                maxUses,
                prebind: prebind ?? null
            }
        });

    } catch (error) {
        console.error("Generate code by id error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

/**
 * 批量生成激活码
 * POST /code/batch-generate-by-id
 * Body: {
 *   "productId": number,
 *   "codeValidDuration": number,
 *   "useMaxDuration": number,
 *   "maxUses": number,
 *   "count": number,             // 生成数量 (1-100)
 *   "prebind"?: number | null
 * }
 */
superAdmin.post("/code/batch-generate-by-id", async (c) => {
    try {
        const isAuthed = await authSuperAdmin(c);

        if (!isAuthed) {
            return c.text("Not Found", 404);
        }

        const body = await c.req.json();
        const { productId, codeValidDuration, useMaxDuration, maxUses, count, prebind } = body;

        // 参数验证
        if (!productId || typeof productId !== "number" || !Number.isInteger(productId)) {
            return c.json({ success: false, message: "Invalid productId" }, 400);
        }

        if (typeof codeValidDuration !== "number" || codeValidDuration <= 0 || !Number.isInteger(codeValidDuration)) {
            return c.json({ success: false, message: "Invalid codeValidDuration" }, 400);
        }

        if (typeof useMaxDuration !== "number" || useMaxDuration <= 0 || !Number.isInteger(useMaxDuration)) {
            return c.json({ success: false, message: "Invalid useMaxDuration" }, 400);
        }

        if (typeof maxUses !== "number" || maxUses <= 0 || !Number.isInteger(maxUses)) {
            return c.json({ success: false, message: "Invalid maxUses" }, 400);
        }

        if (typeof count !== "number" || count < 1 || count > 100 || !Number.isInteger(count)) {
            return c.json({ success: false, message: "Invalid count (must be 1-100)" }, 400);
        }

        if (prebind !== undefined && prebind !== null) {
            if (typeof prebind !== "number" || !Number.isInteger(prebind)) {
                return c.json({ success: false, message: "Invalid prebind" }, 400);
            }
        }

        // 检查产品是否存在
        if (!await Product.existsId(c.env.AUTH_KV, productId)) {
            return c.json({ success: false, message: "Product not found" }, 404);
        }

        // 获取产品密钥
        const [ok, productKey] = await Product.getKey(c.env.AUTH_KV, productId);

        if (!ok || !productKey) {
            return c.json({ success: false, message: "Failed to get product key" }, 500);
        }

        // 批量生成
        const codes: string[] = [];
        const prebindValue = prebind ?? null;

        for (let i = 0; i < count; i++) {
            const code = code_v1_generate(
                productKey,
                productId,
                codeValidDuration,
                useMaxDuration,
                maxUses,
                prebindValue
            );

            if (!code) {
                return c.json({
                    success: false,
                    message: `Code generation failed at index ${i + 1}`
                }, 500);
            }

            codes.push(code);
        }

        return c.json({
            success: true,
            message: `Successfully generated ${count} activation codes`,
            data: {
                codes,
                productId,
                codeValidDuration,
                useMaxDuration,
                maxUses,
                count,
                prebind: prebindValue
            }
        });

    } catch (error) {
        console.error("Batch generate codes error:", error);
        return c.json({ success: false, message: "Internal server error" }, 500);
    }
});

superAdmin.get("/", async (c) => {
    const isAuthed = await authSuperAdmin(c);
    if (!isAuthed) {
        return c.text("Not Found", 404);
    }
    return c.html(suHtml);
});

export default superAdmin;