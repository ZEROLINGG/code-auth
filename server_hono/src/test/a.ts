// test/a.ts

import {Code} from "../tool/code";
import {AES} from "../tool/aes";


const aseKey = "97145111-9d24-43f9-b5f1-2db9d2afbdc9";
const productID = "uOHF8As";
const code = await Code._generate(
    aseKey,
    productID,
    7 * 24 * 3600_00000000000,  // 过期时间（7 天）
    30 * 24 * 3600_000, // 激活后有效期（30 天）
    5                  // 最大使用次数
);


console.log("激活码:", code);
console.log("长度:", code.length)

console.log("验证:", await Code.verify(aseKey, code, productID))
