// sdk/server/wasm/src/lib.rs

/// 该sdk旨在提供安全便捷的各种数据处理工具
/// 由内部库封装各种易出错细节
///
mod utils;

use wasm_bindgen::prelude::*;

use lib::base::{Base64, Base85, Base91, Encoder};
use lib::compress::{Zstd, Lz4, Gzip, Compressor};
use lib::hash::{Sha256, Sha512, Sha512_256, Blake3, Hasher};
use lib::aead::{Aes128Gcm, Aes256Gcm, Aes128GcmSiv, Aes256GcmSiv, ChaCha20Poly1305, XChaCha20Poly1305, Cipher};
use lib::rsa::{Rsa2048, Rsa4096, AsymmetricCipher, check_pubkey};
use lib::code::{V1, V2, CodeDesc};
use lib::kdf::{Pbkdf2HmacSha256, Kdf, Pbkdf2HmacSha256High, Pbkdf2HmacSha512, Argon2idDefault, Argon2idHigh, Argon2i, ScryptDefault, ScryptHigh, HkdfSha256, HkdfSha512};
use lib::ecc::{EccCipher, P256, Secp256k1, P384};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


/*
/////////////
宏定义
/////////////
*/

/// 展开 Encoder 的四个 WASM 绑定函数：
///   {prefix}_encode_from_str / _from_bytes -> String
///   {prefix}_decode_to_str   / _to_bytes   -> Option<String/Vec<u8>>
///
/// 用法：impl_encoder!(base64, Base64);
macro_rules! impl_encoder {
    ($prefix:ident, $impl:ident) => {
        paste::paste! {
            /// 将字符串编码为 Base 编码格式
            ///
            /// # 参数
            /// * `input` - 要编码的字符串
            ///
            /// # 返回
            /// 编码后的字符串
            #[wasm_bindgen]
            pub fn [<$prefix _encode_from_str>](input: &str) -> String {
                $impl::encode(input)
            }

            /// 将字节数组编码为 Base 编码格式
            ///
            /// # 参数
            /// * `input` - 要编码的字节数组
            ///
            /// # 返回
            /// 编码后的字符串
            #[wasm_bindgen]
            pub fn [<$prefix _encode_from_bytes>](input: &[u8]) -> String {
                $impl::encode(input)
            }

            /// 将编码字符串解码为 UTF-8 字符串
            ///
            /// # 参数
            /// * `input` - 编码后的字符串
            ///
            /// # 返回
            /// 解码成功返回 `Some(String)`，失败返回 `None`
            #[wasm_bindgen]
            pub fn [<$prefix _decode_to_str>](input: &str) -> Option<String> {
                let bytes = $impl::decode(input)?;
                String::from_utf8(bytes).ok()
            }

            /// 将编码字符串解码为字节数组
            ///
            /// # 参数
            /// * `input` - 编码后的字符串
            ///
            /// # 返回
            /// 解码成功返回 `Some(Vec<u8>)`，失败返回 `None`
            #[wasm_bindgen]
            pub fn [<$prefix _decode_to_bytes>](input: &str) -> Option<Vec<u8>> {
                $impl::decode(input)
            }
        }
    };
}

/// 展开 Compressor 的四个 WASM 绑定函数：
///   {prefix}_compress_from_str / _from_bytes -> Option<Vec<u8>>
///   {prefix}_decompress_to_str / _to_bytes   -> Option<String/Vec<u8>>
///
/// 用法：impl_compressor!(zstd, Zstd);
macro_rules! impl_compressor {
    ($prefix:ident, $impl:ident) => {
        paste::paste! {
            /// 压缩字符串数据
            ///
            /// 将 UTF-8 字符串压缩为二进制数据。
            ///
            /// # 参数
            /// - `input`: 要压缩的字符串
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 压缩成功，返回压缩后的字节数组
            /// - `None`: 压缩失败
            ///
            /// # 示例
            /// ```javascript
            /// const compressed = zstd_compress_from_str("Hello, World!");
            /// if (compressed) {
            ///     console.log("压缩成功，大小:", compressed.length);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _compress_from_str>](input: &str) -> Option<Vec<u8>> {
                $impl::compress(input)
            }

            /// 压缩字节数组
            ///
            /// 将任意二进制数据压缩为更小的字节数组。
            ///
            /// # 参数
            /// - `input`: 要压缩的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 压缩成功，返回压缩后的字节数组
            /// - `None`: 压缩失败
            ///
            /// # 示例
            /// ```javascript
            /// const data = new Uint8Array([1, 2, 3, 4, 5]);
            /// const compressed = lz4_compress_from_bytes(data);
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _compress_from_bytes>](input: &[u8]) -> Option<Vec<u8>> {
                $impl::compress(input)
            }

            /// 解压缩为 UTF-8 字符串
            ///
            /// 将压缩的字节数据解压并转换为字符串。
            ///
            /// # 参数
            /// - `input`: 压缩后的字节数组
            ///
            /// # 返回
            /// - `Some(String)`: 解压成功且数据是有效的 UTF-8
            /// - `None`: 解压失败或数据不是有效的 UTF-8
            ///
            /// # 安全性
            /// - 自动防御解压炸弹（最大解压比 1024:1）
            /// - 限制最大解压大小为 256 MiB
            ///
            /// # 错误情况
            /// - 输入数据损坏或格式不正确
            /// - 解压后的数据不是有效的 UTF-8
            /// - 检测到解压炸弹攻击
            ///
            /// # 示例
            /// ```javascript
            /// const text = gzip_decompress_to_str(compressed);
            /// if (text) {
            ///     console.log("原始文本:", text);
            /// } else {
            ///     console.error("解压失败");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decompress_to_str>](input: &[u8]) -> Option<String> {
                let bytes = $impl::decompress(input)?;
                String::from_utf8(bytes).ok()
            }

            /// 解压缩为字节数组
            ///
            /// 将压缩的字节数据解压为原始二进制数据。
            ///
            /// # 参数
            /// - `input`: 压缩后的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 解压成功，返回原始字节数组
            /// - `None`: 解压失败
            ///
            /// # 安全性
            /// - 自动防御解压炸弹（最大解压比 1024:1）
            /// - 限制最大解压大小为 256 MiB
            /// - 在解压前验证声明的大小（如果格式支持）
            ///
            /// # 错误情况
            /// - 输入数据损坏或格式不正确
            /// - 检测到解压炸弹攻击（声明大小超过安全限制）
            /// - 实际解压大小超过限制
            ///
            /// # 示例
            /// ```javascript
            /// const original = zstd_decompress_to_bytes(compressed);
            /// if (original) {
            ///     console.log("解压成功，大小:", original.length);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decompress_to_bytes>](input: &[u8]) -> Option<Vec<u8>> {
                $impl::decompress(input)
            }
        }
    };
}

/// 展开 Hasher 的四个 WASM 绑定函数：
///   {prefix}_digest_from_str     / _from_bytes -> String   (hex)
///   {prefix}_digest_raw_from_str / _from_bytes -> Vec<u8>  (raw bytes)
///
/// 用法：impl_hasher!(sha256, Sha256);
macro_rules! impl_hasher {
    ($prefix:ident, $impl:ident) => {
        paste::paste! {
            /// 计算 {prefix} 哈希值并返回十六进制字符串（小写）
            ///
            /// 这是最常用的哈希接口。SHA-256 返回 64 字符，SHA-512 返回 128 字符，
            /// Blake3 返回 64 字符。
            ///
            /// # 参数
            /// - `input`: 需要计算哈希的字符串
            #[wasm_bindgen]
            pub fn [<$prefix _digest_from_str>](input: &str) -> String {
                $impl::digest_hex(input)
            }

            /// 计算 {prefix} 哈希值并返回十六进制字符串（小写）
            ///
            /// 这是最常用的哈希接口。
            ///
            /// # 参数
            /// - `input`: 需要计算哈希的字节数组
            #[wasm_bindgen]
            pub fn [<$prefix _digest_from_bytes>](input: &[u8]) -> String {
                $impl::digest_hex(input)
            }

            /// 计算 {prefix} 原始哈希值并返回二进制数据
            ///
            /// 返回原始二进制摘要（长度：SHA-256 为 32 字节，SHA-512 为 64 字节，
            /// Blake3 为 32 字节）。推荐用于密钥派生、HMAC、签名等需要二进制输出的场景。
            ///
            /// # 参数
            /// - `input`: 需要计算哈希的字符串
            #[wasm_bindgen]
            pub fn [<$prefix _digest_raw_from_str>](input: &str) -> Vec<u8> {
                $impl::digest_vec(input)
            }

            /// 计算 {prefix} 原始哈希值并返回二进制数据
            ///
            /// 返回原始二进制摘要。推荐用于需要二进制输出的密码学场景。
            ///
            /// # 参数
            /// - `input`: 需要计算哈希的字节数组
            #[wasm_bindgen]
            pub fn [<$prefix _digest_raw_from_bytes>](input: &[u8]) -> Vec<u8> {
                $impl::digest_vec(input)
            }
        }
    };
}

/// 展开 Cipher 的四个 WASM 绑定函数：
///   {prefix}_encrypt_from_str   / _from_bytes -> Option<Vec<u8>>
///   {prefix}_decrypt_to_str     / _to_bytes   -> Option<String/Vec<u8>>
macro_rules! impl_cipher {
    ($prefix:ident, $impl:ident) => {
        paste::paste! {
            /// 加密字符串（AEAD 认证加密）
            ///
            /// 使用认证加密模式（AEAD）加密 UTF-8 字符串，自动生成随机 nonce 并附加认证标签。
            ///
            /// # 参数
            /// - `key`: 加密密钥（必须符合算法要求的长度）
            ///   - AES-128: 16 字节
            ///   - AES-256: 32 字节
            ///   - ChaCha20/XChaCha20: 32 字节
            /// - `plaintext`: 要加密的字符串
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 加密成功，返回 `[nonce || ciphertext || tag]` 格式的数据
            /// - `None`: 加密失败（通常是密钥长度不正确）
            ///
            /// # 输出格式
            /// ```text
            /// [  nonce  |  ciphertext  |  tag  ]
            ///   12/24 B   明文长度        16 B
            /// ```
            ///
            /// # 安全特性
            /// - **机密性**：数据加密，防止窃听
            /// - **完整性**：防篡改，任何修改都会导致解密失败
            /// - **认证性**：验证数据来源
            /// - **随机 nonce**：每次加密使用新的随机数，确保相同明文产生不同密文
            ///
            /// # 注意事项
            /// - **密钥必须保密**：泄露密钥将导致所有数据可被解密
            /// - **密钥长度严格**：不符合长度要求将返回 `None`
            /// - **输出包含 nonce**：解密时需要完整的输出数据
            ///
            /// # 示例
            /// ```javascript
            /// // 生成 32 字节密钥（建议使用 KDF 从密码派生）
            /// const key = crypto.getRandomValues(new Uint8Array(32));
            ///
            /// const plaintext = "敏感数据";
            /// const ciphertext = aes256gcm_encrypt_from_str(key, plaintext);
            ///
            /// if (ciphertext) {
            ///     console.log("加密成功，长度:", ciphertext.length);
            ///     // 可安全存储或传输 ciphertext
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _encrypt_from_str>](key: &[u8], plaintext: &str) -> Option<Vec<u8>> {
                $impl::encrypt(key, plaintext)
            }

            /// 加密字节数组（AEAD 认证加密）
            ///
            /// 使用认证加密模式加密任意二进制数据，提供机密性和完整性保护。
            ///
            /// # 参数
            /// - `key`: 加密密钥（长度见 `encrypt_from_str` 说明）
            /// - `plaintext`: 要加密的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 加密成功，格式为 `[nonce || ciphertext || tag]`
            /// - `None`: 加密失败
            ///
            /// # 用途
            /// - 加密文件
            /// - 保护二进制协议数据
            /// - 加密序列化对象
            ///
            /// # 性能
            /// - 加密速度快（硬件加速）
            /// - 输出大小 = 输入大小 + nonce 长度 + 16 字节（tag）
            ///
            /// # 示例
            /// ```javascript
            /// const key = new Uint8Array(32); // 实际使用中应使用安全密钥
            /// crypto.getRandomValues(key);
            ///
            /// const fileData = new Uint8Array([...]); // 文件内容
            /// const encrypted = chacha20poly1305_encrypt_from_bytes(key, fileData);
            ///
            /// if (encrypted) {
            ///     // 保存到加密文件
            ///     await saveEncryptedFile(encrypted);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _encrypt_from_bytes>](key: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
                $impl::encrypt(key, plaintext)
            }

            /// 解密为 UTF-8 字符串（AEAD 认证解密）
            ///
            /// 解密数据并验证完整性，返回原始字符串。
            ///
            /// # 参数
            /// - `key`: 解密密钥（必须与加密时使用的密钥相同）
            /// - `ciphertext`: 加密数据（必须包含 nonce 和 tag）
            ///
            /// # 返回
            /// - `Some(String)`: 解密成功且数据是有效的 UTF-8
            /// - `None`: 解密失败（可能的原因见下方）
            ///
            /// # 失败原因
            /// - **密钥错误**：与加密时使用的密钥不同
            /// - **数据被篡改**：认证标签验证失败
            /// - **数据损坏**：nonce 或密文不完整
            /// - **密钥长度错误**：不符合算法要求
            /// - **非 UTF-8 数据**：解密后的数据不是有效的 UTF-8
            ///
            /// # 安全性
            /// - **认证优先解密**：先验证标签再解密，防止 padding oracle 攻击
            /// - **常量时间比较**：防止时序攻击
            /// - **失败即销毁**：验证失败时不返回任何部分明文
            ///
            /// # 示例
            /// ```javascript
            /// const key = loadKey(); // 加载密钥
            /// const encrypted = loadEncryptedData(); // 加载密文
            ///
            /// const plaintext = aes256gcm_decrypt_to_str(key, encrypted);
            ///
            /// if (plaintext) {
            ///     console.log("解密成功:", plaintext);
            /// } else {
            ///     console.error("解密失败：密钥错误或数据已损坏");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decrypt_to_str>](key: &[u8], ciphertext: &[u8]) -> Option<String> {
                let bytes = $impl::decrypt(key, ciphertext)?;
                String::from_utf8(bytes).ok()
            }

            /// 解密为字节数组（AEAD 认证解密）
            ///
            /// 解密数据并验证完整性，返回原始二进制数据。
            ///
            /// # 参数
            /// - `key`: 解密密钥（必须与加密时使用的密钥相同）
            /// - `ciphertext`: 加密数据（格式：`[nonce || ciphertext || tag]`）
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 解密并验证成功
            /// - `None`: 解密失败
            ///
            /// # 最小密文长度
            /// - AES-GCM/GCM-SIV: 28 字节（12 B nonce + 0 B plaintext + 16 B tag）
            /// - ChaCha20-Poly1305: 28 字节（12 B nonce + 16 B tag）
            /// - XChaCha20-Poly1305: 40 字节（24 B nonce + 16 B tag）
            ///
            /// # 性能建议
            /// - 大文件解密时考虑分块处理
            /// - 先验证密钥长度再解密，避免无效计算
            ///
            /// # 用途
            /// - 解密文件
            /// - 解密二进制协议数据
            /// - 解密序列化对象
            ///
            /// # 示例
            /// ```javascript
            /// const key = new Uint8Array(16); // AES-128 密钥
            /// // ... 加载密钥数据 ...
            ///
            /// const encrypted = loadEncryptedFile();
            /// const decrypted = aes128gcm_decrypt_to_bytes(key, encrypted);
            ///
            /// if (decrypted) {
            ///     // 验证文件完整性（可选）
            ///     const hash = sha256_digest_from_bytes(decrypted);
            ///     console.log("文件哈希:", hash);
            /// } else {
            ///     console.error("解密失败");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decrypt_to_bytes>](key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
                $impl::decrypt(key, ciphertext)
            }
        }
    };
}

/// 展开 RSA KeyPair 结构体及其 getter，以及对应的 generate/encrypt/decrypt/sign/verify 绑定。
///
/// 用法：impl_rsa!(Rsa2048, rsa2048, Rsa2048KeyPair);
macro_rules! impl_rsa {
    ($impl:ident, $prefix:ident, $keypair:ident) => {
        paste::paste! {
            /// RSA 密钥对
            ///
            /// 包含 DER 格式的公钥和私钥字节。
            ///
            /// # 密钥格式
            /// - **公钥**: SubjectPublicKeyInfo (SPKI) DER 格式
            /// - **私钥**: PKCS#8 DER 格式
            ///
            /// # 安全建议
            /// - 私钥必须严格保密，切勿传输或明文存储
            /// - 公钥可以公开分发
            /// - 建议使用完成后立即释放私钥内存
            #[wasm_bindgen]
            pub struct $keypair {
                public_key: Vec<u8>,
                private_key: Vec<u8>,
            }

            #[wasm_bindgen]
            impl $keypair {
                /// 获取 DER 格式的公钥字节
                ///
                /// 返回 SubjectPublicKeyInfo (SPKI) DER 编码的公钥，
                /// 可用于加密、验签及传输给其他方。
                #[wasm_bindgen(getter)]
                pub fn public_key(&self) -> Vec<u8> {
                    self.public_key.clone()
                }

                /// 获取 DER 格式的私钥字节
                ///
                /// 返回 PKCS#8 DER 编码的私钥，用于解密和签名。
                ///
                /// # 安全警告
                /// ⚠️ **私钥必须严格保密**，请妥善存储，切勿：
                /// - 通过网络传输
                /// - 记录到日志
                /// - 存储在不安全的位置
                #[wasm_bindgen(getter)]
                pub fn private_key(&self) -> Vec<u8> {
                    self.private_key.clone()
                }
            }

            /// 生成 RSA 密钥对
            ///
            /// 使用系统安全随机数生成器（OsRng / Web Crypto API）生成新的 RSA 密钥对。
            ///
            /// # 返回
            /// - `Some(KeyPair)`: 生成成功，包含 DER 格式的公钥和私钥
            /// - `None`: 生成失败（随机数生成器不可用）
            ///
            /// # 密钥规格
            /// - **RSA-2048**：公钥指数 e = 65537，适合一般场景
            /// - **RSA-4096**：公钥指数 e = 65537，适合高安全性需求
            ///
            /// # 性能说明
            /// RSA 密钥生成是计算密集型操作：
            /// - RSA-2048：约需 100~500ms
            /// - RSA-4096：约需 1~5s
            ///
            /// 建议在非关键路径上预生成密钥或异步执行。
            ///
            /// # 示例
            /// ```javascript
            /// const keypair = rsa2048_generate_keypair();
            ///
            /// if (keypair) {
            ///     const publicKey  = keypair.public_key;  // Uint8Array (DER)
            ///     const privateKey = keypair.private_key; // Uint8Array (DER)
            ///
            ///     // 公钥可以公开分发
            ///     await sendPublicKey(publicKey);
            ///
            ///     // 私钥必须安全存储
            ///     await secureStore(privateKey);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _generate_keypair>]() -> Option<$keypair> {
                let (public_key, private_key) = $impl::generate_keypair()?;
                Some($keypair { public_key, private_key })
            }

            /// 使用 RSA 公钥加密字符串（OAEP 填充）
            ///
            /// 使用公钥对 UTF-8 字符串进行非对称加密。
            ///
            /// # 参数
            /// - `public_key`: DER 格式的 RSA 公钥（SPKI）
            /// - `plaintext`: 要加密的字符串
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 加密成功，返回密文字节
            /// - `None`: 加密失败（公钥格式错误或明文过长）
            ///
            /// # 填充方案
            /// - **RSA-2048**：OAEP + SHA-256（最大明文 190 字节）
            /// - **RSA-4096**：OAEP + SHA-512（最大明文 446 字节）
            ///
            /// # 明文长度限制
            /// RSA 加密有严格的长度上限，超出将导致加密失败：
            /// - RSA-2048/OAEP-SHA256：最大 **190 字节**
            /// - RSA-4096/OAEP-SHA512：最大 **446 字节**
            ///
            /// > 如需加密大数据，建议使用混合加密：
            /// > 随机生成 AES 密钥加密数据，再用 RSA 加密该 AES 密钥。
            ///
            /// # 安全特性
            /// - **OAEP 填充**：防止选择明文攻击（CPA）
            /// - **随机化**：每次加密输出不同，防止重放攻击
            /// - **单向性**：只有持有私钥方才能解密
            ///
            /// # 示例
            /// ```javascript
            /// const publicKey = loadPublicKey(); // DER 格式公钥
            ///
            /// // 适合加密小数据（如 AES 密钥、token 等）
            /// const aesKey = crypto.getRandomValues(new Uint8Array(32));
            /// const encryptedKey = rsa2048_encrypt_from_bytes(publicKey, aesKey);
            ///
            /// if (encryptedKey) {
            ///     console.log("密钥加密成功，密文长度:", encryptedKey.length); // 256 字节
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _encrypt_from_str>](public_key: &[u8], plaintext: &str) -> Option<Vec<u8>> {
                $impl::encrypt(public_key, plaintext)
            }

            /// 使用 RSA 公钥加密字节数组（OAEP 填充）
            ///
            /// 使用公钥对任意二进制数据进行非对称加密。
            ///
            /// # 参数
            /// - `public_key`: DER 格式的 RSA 公钥（SPKI）
            /// - `plaintext`: 要加密的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 加密成功
            /// - `None`: 加密失败（公钥格式错误或明文超出长度限制）
            ///
            /// # 典型用途
            /// - 加密对称密钥（AES、ChaCha20 等）实现混合加密
            /// - 加密短凭证或 token
            /// - 密钥交换
            ///
            /// # 示例
            /// ```javascript
            /// // 混合加密示例
            /// const publicKey = recipientPublicKey;
            ///
            /// // 1. 生成随机 AES 密钥
            /// const aesKey = crypto.getRandomValues(new Uint8Array(32));
            ///
            /// // 2. 用 AES 加密大数据
            /// const encryptedData = aes256gcm_encrypt_from_bytes(aesKey, largeData);
            ///
            /// // 3. 用 RSA 加密 AES 密钥
            /// const encryptedAesKey = rsa4096_encrypt_from_bytes(publicKey, aesKey);
            ///
            /// // 4. 传输 encryptedAesKey + encryptedData
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _encrypt_from_bytes>](public_key: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
                $impl::encrypt(public_key, plaintext)
            }

            /// 使用 RSA 私钥解密为 UTF-8 字符串（OAEP 填充）
            ///
            /// 使用私钥解密密文并转换为字符串。
            ///
            /// # 参数
            /// - `private_key`: DER 格式的 RSA 私钥（PKCS#8）
            /// - `ciphertext`: 要解密的密文字节
            ///
            /// # 返回
            /// - `Some(String)`: 解密成功且数据是有效的 UTF-8
            /// - `None`: 解密失败（密钥错误、数据损坏或非 UTF-8）
            ///
            /// # 失败原因
            /// - **私钥不匹配**：不是对应的私钥
            /// - **数据损坏**：密文被篡改或截断
            /// - **格式错误**：私钥不是有效的 PKCS#8 DER 格式
            /// - **非 UTF-8**：解密后的数据不是有效的 UTF-8 文本
            ///
            /// # 安全性
            /// - **常量时间解密**：防止时序侧信道攻击
            /// - **OAEP**：防止选择密文攻击（CCA）
            ///
            /// # 示例
            /// ```javascript
            /// const privateKey = await loadPrivateKey(); // 从安全存储加载
            /// const ciphertext = receiveCiphertext();
            ///
            /// const plaintext = rsa2048_decrypt_to_str(privateKey, ciphertext);
            ///
            /// if (plaintext) {
            ///     console.log("解密成功:", plaintext);
            /// } else {
            ///     console.error("解密失败：密钥错误或数据已损坏");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decrypt_to_str>](private_key: &[u8], ciphertext: &[u8]) -> Option<String> {
                let bytes = $impl::decrypt(private_key, ciphertext)?;
                String::from_utf8(bytes).ok()
            }

            /// 使用 RSA 私钥解密为字节数组（OAEP 填充）
            ///
            /// 使用私钥解密密文，返回原始二进制数据。
            ///
            /// # 参数
            /// - `private_key`: DER 格式的 RSA 私钥（PKCS#8）
            /// - `ciphertext`: 要解密的密文字节
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 解密成功
            /// - `None`: 解密失败
            ///
            /// # 典型用途
            /// - 解密对称密钥（混合加密的逆操作）
            /// - 解密二进制凭证
            ///
            /// # 示例
            /// ```javascript
            /// // 混合解密示例
            /// const privateKey = await loadPrivateKey();
            ///
            /// // 1. 用 RSA 解密 AES 密钥
            /// const aesKey = rsa4096_decrypt_to_bytes(privateKey, encryptedAesKey);
            ///
            /// if (aesKey) {
            ///     // 2. 用 AES 密钥解密数据
            ///     const data = aes256gcm_decrypt_to_bytes(aesKey, encryptedData);
            ///     console.log("解密完成，数据长度:", data?.length);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _decrypt_to_bytes>](private_key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
                $impl::decrypt(private_key, ciphertext)
            }

            /// 使用 RSA 私钥对字符串签名（PSS 填充）
            ///
            /// 使用私钥对 UTF-8 字符串生成数字签名，可供他人用公钥验证。
            ///
            /// # 参数
            /// - `private_key`: DER 格式的 RSA 私钥（PKCS#8）
            /// - `message`: 要签名的字符串
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 签名成功，返回签名字节
            /// - `None`: 签名失败（私钥格式错误）
            ///
            /// # 签名方案
            /// - **RSA-2048**：PSS + SHA-256，签名长度固定 **256 字节**
            /// - **RSA-4096**：PSS + SHA-512，签名长度固定 **512 字节**
            ///
            /// # 安全特性
            /// - **PSS 填充**：概率性签名，防止伪造攻击
            /// - **随机盐**：每次签名结果不同（但均可验证）
            /// - **盲化签名**：防止私钥信息通过时序攻击泄露
            ///
            /// # 用途
            /// - 软件分发签名（验证来源）
            /// - 文档签名
            /// - 激活码/许可证签发
            ///
            /// # 示例
            /// ```javascript
            /// const privateKey = await loadPrivateKey();
            /// const message = "用户 ID: 12345，权限：admin";
            ///
            /// const signature = rsa2048_sign_from_str(privateKey, message);
            ///
            /// if (signature) {
            ///     console.log("签名长度:", signature.length); // 256 字节
            ///     // 将 message + signature 一起发送给验证方
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _sign_from_str>](private_key: &[u8], message: &str) -> Option<Vec<u8>> {
                $impl::sign(private_key, message)
            }

            /// 使用 RSA 私钥对字节数组签名（PSS 填充）
            ///
            /// 使用私钥对任意二进制数据生成数字签名。
            ///
            /// # 参数
            /// - `private_key`: DER 格式的 RSA 私钥（PKCS#8）
            /// - `message`: 要签名的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 签名成功
            /// - `None`: 签名失败
            ///
            /// # 用途
            /// - 固件/镜像完整性验证
            /// - 二进制协议消息认证
            /// - 文件哈希签名
            ///
            /// # 性能建议
            /// 对大文件签名时，建议先哈希再签名：
            /// ```javascript
            /// // 推荐：先哈希大文件，再对哈希值签名
            /// const fileHash = sha256_digest_raw_from_bytes(largeFile);
            /// const signature = rsa4096_sign_from_bytes(privateKey, fileHash);
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _sign_from_bytes>](private_key: &[u8], message: &[u8]) -> Option<Vec<u8>> {
                $impl::sign(private_key, message)
            }

            /// 使用 RSA 公钥验证字符串签名（PSS 填充）
            ///
            /// 使用公钥验证签名是否由对应私钥持有者生成。
            ///
            /// # 参数
            /// - `public_key`: DER 格式的 RSA 公钥（SPKI）
            /// - `message`: 被签名的原始字符串
            /// - `signature`: 要验证的签名字节
            ///
            /// # 返回
            /// - `true`: 签名有效，消息真实且完整
            /// - `false`: 签名无效（消息被篡改、签名伪造或密钥不匹配）
            ///
            /// # 验证失败原因
            /// - 消息内容与签名时不一致（被篡改）
            /// - 签名不是由对应私钥生成的（伪造）
            /// - 公钥格式错误或与签名密钥不匹配
            /// - 签名字节损坏或截断
            ///
            /// # 安全性
            /// - **常量时间比较**：防止时序攻击
            /// - **PSS 验证**：防止签名伪造
            ///
            /// # 示例
            /// ```javascript
            /// const publicKey  = loadPublicKey();
            /// const message    = "用户 ID: 12345，权限：admin";
            /// const signature  = receiveSignature();
            ///
            /// const isValid = rsa2048_verify_from_str(publicKey, message, signature);
            ///
            /// if (isValid) {
            ///     console.log("✅ 签名验证通过，消息可信");
            ///     grantAccess();
            /// } else {
            ///     console.error("❌ 签名验证失败，消息可能被篡改");
            ///     denyAccess();
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _verify_from_str>](public_key: &[u8], message: &str, signature: &[u8]) -> bool {
                $impl::verify(public_key, message, signature)
            }

            /// 使用 RSA 公钥验证字节数组签名（PSS 填充）
            ///
            /// 使用公钥验证二进制数据的签名是否有效。
            ///
            /// # 参数
            /// - `public_key`: DER 格式的 RSA 公钥（SPKI）
            /// - `message`: 被签名的原始字节数组
            /// - `signature`: 要验证的签名字节
            ///
            /// # 返回
            /// - `true`: 签名有效
            /// - `false`: 签名无效
            ///
            /// # 用途
            /// - 固件更新验证（防止恶意固件）
            /// - 软件包完整性校验
            /// - 二进制协议消息认证
            ///
            /// # 示例
            /// ```javascript
            /// // 固件验证示例
            /// const vendorPublicKey = loadVendorPublicKey();
            /// const firmware        = await downloadFirmware();
            /// const signature       = await downloadSignature();
            ///
            /// // 对固件哈希验签（与签名时保持一致）
            /// const firmwareHash = sha256_digest_raw_from_bytes(firmware);
            /// const isValid = rsa4096_verify_from_bytes(
            ///     vendorPublicKey,
            ///     firmwareHash,
            ///     signature
            /// );
            ///
            /// if (isValid) {
            ///     console.log("✅ 固件来源可信，允许安装");
            /// } else {
            ///     console.error("❌ 固件验证失败，拒绝安装");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _verify_from_bytes>](public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
                $impl::verify(public_key, message, signature)
            }
        }
    };
}

/// 展开 Kdf 的四个 WASM 绑定函数：
///   {prefix}_derive_from_str     / _from_bytes -> Option<Vec<u8>>
///   {prefix}_derive_hex_from_str / _from_bytes -> Option<String>
///
/// 用法：impl_kdf!(pbkdf2_sha256, Pbkdf2HmacSha256, 32);
macro_rules! impl_kdf {
    ($prefix:ident, $impl:ident, $default_len:expr) => {
        paste::paste! {
            /// 从字符串密码派生密钥（返回原始字节）
            ///
            /// 使用密钥派生函数（KDF）将用户密码转换为加密密钥。
            ///
            /// # 参数
            /// - `password`: 用户密码或口令（任意长度 UTF-8 字符串）
            /// - `salt`: 盐值，**强烈建议使用 16 字节以上的随机数据**
            /// - `output_len`: 期望输出的密钥长度（字节），传 `null` 则使用默认值
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 派生成功，长度恰好为 `output_len`（或默认值）
            /// - `None`: 参数无效（空密码、盐值过短、长度为 0 等）
            ///
            /// # 默认输出长度
            /// 各算法默认输出长度：
            /// - PBKDF2 / Argon2 / scrypt：**32 字节**（适合 AES-256 密钥）
            /// - HKDF-SHA512：**64 字节**
            ///
            /// # 算法参数速查
            ///
            /// | 算法 | 迭代/内存成本 | 耗时估计 | 适用场景 |
            /// |------|-------------|---------|---------|
            /// | `pbkdf2_sha256` | 100,000 次 | ~100ms | 通用兼容 |
            /// | `pbkdf2_sha256_high` | 600,000 次 | ~600ms | Apple 平台 |
            /// | `pbkdf2_sha512` | 210,000 次 | ~200ms | 通用兼容 |
            /// | `argon2id_default` | 19MB / 2轮 | ~200ms | 推荐首选 |
            /// | `argon2id_high` | 256MB / 3轮 | ~1s+ | 高安全场景 |
            /// | `argon2i` | 64MB / 3轮 | ~500ms | 抗侧信道 |
            /// | `scrypt_default` | 32MB | ~300ms | 资源受限 |
            /// | `scrypt_high` | 128MB | ~1s+ | 高安全场景 |
            /// | `hkdf_sha256` | 极快 | <1ms | 仅限高熵输入 |
            /// | `hkdf_sha512` | 极快 | <1ms | 仅限高熵输入 |
            ///
            /// # 安全要求
            /// - **盐值必须随机**：使用 `crypto.getRandomValues()` 生成，不可重复使用
            /// - **盐值必须存储**：解密/验证时需要相同盐值
            /// - **密码不能为空**：空密码将返回 `None`
            /// - **HKDF 不适合低熵密码**：密码应先经过 PBKDF2/Argon2 处理
            ///
            /// # 示例
            /// ```javascript
            /// // 生成随机盐值（每次注册/加密时生成新盐）
            /// const salt = crypto.getRandomValues(new Uint8Array(16));
            /// const password = "用户密码";
            ///
            /// // 派生 32 字节密钥（用于 AES-256）
            /// const key = argon2id_default_derive_from_str(password, salt, 32);
            ///
            /// if (key) {
            ///     console.log("密钥长度:", key.length); // 32
            ///     // 使用派生的密钥加密数据
            ///     const encrypted = aes256gcm_encrypt_from_bytes(key, data);
            /// }
            ///
            /// // 使用默认长度（传 null 或 undefined）
            /// const defaultKey = pbkdf2_sha256_derive_from_str(password, salt, null);
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _derive_from_str>](
                password: &str,
                salt: &[u8],
                output_len: Option<usize>,
            ) -> Option<Vec<u8>> {
                let len = output_len.unwrap_or($default_len);
                $impl::derive(password, salt, len)
            }

            /// 从字节密码派生密钥（返回原始字节）
            ///
            /// 使用密钥派生函数（KDF）从任意二进制密钥材料派生新密钥，
            /// 适合从已有密钥派生子密钥或扩展密钥长度。
            ///
            /// # 参数
            /// - `password`: 密钥材料（二进制密码、主密钥或密钥材料）
            /// - `salt`: 盐值，**PBKDF2/scrypt 建议 ≥16 字节，Argon2 要求 ≥8 字节**
            /// - `output_len`: 期望输出的密钥长度（字节），传 `null` 则使用默认值
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 派生成功
            /// - `None`: 参数无效
            ///
            /// # 与 `derive_from_str` 的区别
            /// - `derive_from_str`：适合用户输入的文本密码
            /// - `derive_from_bytes`：适合已有二进制密钥材料（如 ECDH 共享密钥）
            ///
            /// # HKDF 特殊说明
            /// HKDF 专为**高熵密钥扩展**设计：
            /// - ✅ 适合：ECDH 共享密钥扩展、主密钥派生子密钥
            /// - ❌ 不适合：用户密码（熵值太低）
            ///
            /// # 失败原因
            /// - `password` 为空
            /// - `output_len` 为 0
            /// - `salt` 对于 Argon2 不足 8 字节
            /// - 输出长度超过算法上限（HKDF-SHA256 最大 8160 字节）
            ///
            /// # 示例
            /// ```javascript
            /// // 场景一：从 ECDH 共享密钥派生加密密钥和 MAC 密钥
            /// const sharedSecret = p256_ecdh_persistent(myPrivKey, peerPubKey);
            ///
            /// if (sharedSecret) {
            ///     const salt = crypto.getRandomValues(new Uint8Array(16));
            ///
            ///     // 派生 64 字节：前 32 字节用于加密，后 32 字节用于 MAC
            ///     const keyMaterial = hkdf_sha256_derive_from_bytes(
            ///         sharedSecret, salt, 64
            ///     );
            ///
            ///     if (keyMaterial) {
            ///         const encKey = keyMaterial.slice(0, 32);
            ///         const macKey = keyMaterial.slice(32, 64);
            ///     }
            /// }
            ///
            /// // 场景二：从主密钥派生多个子密钥
            /// const masterKey = crypto.getRandomValues(new Uint8Array(32));
            /// const context1  = new TextEncoder().encode("encryption-key-v1");
            /// const derivedKey = hkdf_sha512_derive_from_bytes(masterKey, context1, 32);
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _derive_from_bytes>](
                password: &[u8],
                salt: &[u8],
                output_len: Option<usize>,
            ) -> Option<Vec<u8>> {
                let len = output_len.unwrap_or($default_len);
                $impl::derive(password, salt, len)
            }
        }
    };
}


/// 展开 EccCipher 的完整 WASM 绑定函数
///
/// 命名规则：
///   {prefix}_generate_keypair                    -> {prefix}KeyPair
///   {prefix}_sign_from_{input}                   -> Option<Vec<u8>>
///   {prefix}_verify_from_{input}                 -> bool
///   {prefix}_ecdh_ephemeral                      -> Option<EcdhResult>
///   {prefix}_ecdh_persistent                     -> Option<Vec<u8>>
///   {prefix}_ecdh_kdf_hkdf256                    -> Option<EcdhResult>
///
/// 用法：impl_ecc_cipher!(p256, P256, P256KeyPair);
macro_rules! impl_ecc_cipher {
    ($prefix:ident, $impl:ident, $keypair:ident) => {
        paste::paste! {
            /// 生成 ECC 密钥对
            ///
            /// 使用系统安全随机数生成器（OsRng / Web Crypto API）生成新的椭圆曲线密钥对。
            ///
            /// # 返回
            /// - `Some(KeyPair)`: 生成成功，包含压缩格式公钥和原始私钥字节
            /// - `None`: 生成失败（随机数生成器不可用）
            ///
            /// # 密钥格式
            /// - **公钥**: SEC1 压缩格式（33 字节 / P-256、secp256k1；49 字节 / P-384）
            /// - **私钥**: 原始大端整数字节（32 字节 / P-256、secp256k1；48 字节 / P-384）
            ///
            /// # 曲线规格速查
            ///
            /// | 曲线 | 公钥长度 | 私钥长度 | 签名长度 | 安全强度 |
            /// |------|---------|---------|---------|---------|
            /// | P-256 | 33 字节 | 32 字节 | 64 字节 | 128-bit |
            /// | secp256k1 | 33 字节 | 32 字节 | 64 字节 | 128-bit |
            /// | P-384 | 49 字节 | 48 字节 | 96 字节 | 192-bit |
            ///
            /// # 曲线选择建议
            /// - **P-256**：NIST 标准，TLS/PKI 生态广泛支持，推荐通用场景
            /// - **secp256k1**：比特币/以太坊标准，区块链/金融领域首选
            /// - **P-384**：更高安全强度（192-bit），适合高安全需求场景
            ///
            /// # 性能说明
            /// ECC 密钥生成速度极快（< 1ms），远优于 RSA。
            ///
            /// # 示例
            /// ```javascript
            /// const keypair = p256_generate_keypair();
            ///
            /// if (keypair) {
            ///     const publicKey  = keypair.public_key;  // Uint8Array, 33 字节（压缩）
            ///     const privateKey = keypair.private_key; // Uint8Array, 32 字节
            ///
            ///     // 公钥可公开分发用于验签或 ECDH
            ///     await publishPublicKey(publicKey);
            ///
            ///     // 私钥必须安全存储
            ///     await secureStore(privateKey);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _generate_keypair>]() -> Option<$keypair> {
                let (public_key, private_key) = $impl::generate_keypair()?;
                Some($keypair { public_key, private_key })
            }

            /// 使用 ECC 私钥对字符串签名（ECDSA + Blake3）
            ///
            /// 先对消息进行 Blake3 哈希，再使用 ECDSA 签名算法生成数字签名。
            ///
            /// # 参数
            /// - `private_key`: 原始私钥字节（大端整数）
            /// - `message`: 要签名的字符串
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 签名成功，返回 DER 编码的签名字节
            /// - `None`: 签名失败（私钥格式错误或无效）
            ///
            /// # 签名方案
            /// `消息 → Blake3 哈希 → ECDSA 签名`
            ///
            /// - **哈希算法**：Blake3（高性能，抗长度扩展攻击）
            /// - **签名算法**：ECDSA（确定性签名，防 nonce 重用）
            ///
            /// # 签名长度
            /// - P-256 / secp256k1：固定 **64 字节**（r || s 各 32 字节）
            /// - P-384：固定 **96 字节**（r || s 各 48 字节）
            ///
            /// # 安全特性
            /// - **确定性 ECDSA**：相同输入生成相同签名，无随机性，防 nonce 泄露攻击
            /// - **先哈希后签名**：无论消息多长，签名计算量恒定
            ///
            /// # 示例
            /// ```javascript
            /// const privateKey = await loadPrivateKey();
            /// const message    = "转账金额：1000，接收方：Alice";
            ///
            /// const signature = p256_sign_from_str(privateKey, message);
            ///
            /// if (signature) {
            ///     console.log("签名长度:", signature.length); // 64 字节
            ///     // 将 message + signature 一起发送给验证方
            ///     send({ message, signature });
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _sign_from_str>](
                private_key: &[u8],
                message: &str,
            ) -> Option<Vec<u8>> {
                $impl::sign(private_key, message.as_bytes())
            }

            /// 使用 ECC 私钥对字节数组签名（ECDSA + Blake3）
            ///
            /// 先对消息进行 Blake3 哈希，再使用 ECDSA 签名算法生成数字签名。
            ///
            /// # 参数
            /// - `private_key`: 原始私钥字节（大端整数）
            /// - `message`: 要签名的字节数组
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 签名成功
            /// - `None`: 签名失败（私钥无效）
            ///
            /// # 用途
            /// - 固件 / 软件包完整性签名
            /// - 二进制协议消息认证
            /// - 区块链交易签名（secp256k1）
            ///
            /// # 与 `sign_from_str` 的区别
            /// - 内部实现相同（均先 Blake3 哈希再 ECDSA 签名）
            /// - 仅输入类型不同：`sign_from_bytes` 接受任意二进制数据
            ///
            /// # 示例
            /// ```javascript
            /// const privateKey = await loadPrivateKey();
            ///
            /// // 对文件内容签名
            /// const fileBytes = new Uint8Array(await file.arrayBuffer());
            /// const signature = secp256k1_sign_from_bytes(privateKey, fileBytes);
            ///
            /// if (signature) {
            ///     await uploadWithSignature(fileBytes, signature);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _sign_from_bytes>](
                private_key: &[u8],
                message: &[u8],
            ) -> Option<Vec<u8>> {
                $impl::sign(private_key, message)
            }

            /// 使用 ECC 公钥验证字符串签名（ECDSA + Blake3）
            ///
            /// 对消息进行 Blake3 哈希后，验证签名是否由对应私钥持有者生成。
            ///
            /// # 参数
            /// - `public_key`: SEC1 压缩格式公钥字节
            /// - `message`: 被签名的原始字符串（必须与签名时完全一致）
            /// - `signature`: 要验证的签名字节
            ///
            /// # 返回
            /// - `true`: 签名有效，消息真实且完整
            /// - `false`: 签名无效
            ///
            /// # 失败原因
            /// - 消息内容与签名时不一致（被篡改）
            /// - 签名不是由对应私钥生成（伪造攻击）
            /// - 公钥格式错误（非 SEC1 压缩格式）
            /// - 签名字节损坏或长度不正确
            ///
            /// # 安全性
            /// - **常量时间比较**：防止时序侧信道攻击
            /// - **Blake3 预哈希**：防止长度扩展攻击
            ///
            /// # 示例
            /// ```javascript
            /// const publicKey = loadPublicKey(); // SEC1 压缩公钥
            /// const { message, signature } = receiveSignedMessage();
            ///
            /// const isValid = p256_verify_from_str(publicKey, message, signature);
            ///
            /// if (isValid) {
            ///     console.log("✅ 签名有效，消息可信");
            ///     processMessage(message);
            /// } else {
            ///     console.error("❌ 签名验证失败，消息可能被篡改");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _verify_from_str>](
                public_key: &[u8],
                message: &str,
                signature: &[u8],
            ) -> bool {
                $impl::verify(public_key, message.as_bytes(), signature)
            }

            /// 使用 ECC 公钥验证字节数组签名（ECDSA + Blake3）
            ///
            /// 对任意二进制消息进行签名验证。
            ///
            /// # 参数
            /// - `public_key`: SEC1 压缩格式公钥字节
            /// - `message`: 被签名的原始字节数组
            /// - `signature`: 要验证的签名字节
            ///
            /// # 返回
            /// - `true`: 签名有效
            /// - `false`: 签名无效
            ///
            /// # 注意事项
            /// ⚠️ 验证时消息必须与签名时**完全相同的原始数据**：
            /// - 用 `sign_from_str` 签名 → 用 `verify_from_str` 验证
            /// - 用 `sign_from_bytes` 签名 → 用 `verify_from_bytes` 验证
            ///
            /// # 示例
            /// ```javascript
            /// // 固件验证示例
            /// const vendorPublicKey = loadVendorPublicKey();
            /// const firmware        = await downloadFirmware();
            /// const signature       = await downloadSignature();
            ///
            /// const isValid = p384_verify_from_bytes(
            ///     vendorPublicKey,
            ///     firmware,
            ///     signature
            /// );
            ///
            /// if (isValid) {
            ///     console.log("✅ 固件完整性验证通过");
            ///     installFirmware(firmware);
            /// } else {
            ///     console.error("❌ 固件被篡改，拒绝安装");
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _verify_from_bytes>](
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> bool {
                $impl::verify(public_key, message, signature)
            }

            /// ECDH 临时模式密钥交换
            ///
            /// 在本地生成一次性临时密钥对，与对方公钥进行 Diffie-Hellman 交换，
            /// 得到双方共享的秘密值。
            ///
            /// # 参数
            /// - `peer_public_key`: 对方的 SEC1 压缩格式 ECC 公钥
            ///
            /// # 返回
            /// - `Some(EcdhResult)`: 交换成功
            ///   - `ephemeral_public_key`: 本地生成的临时公钥（需发送给对方以完成交换）
            ///   - `shared_secret`: 原始共享秘密（建议通过 KDF 派生后使用）
            /// - `None`: 交换失败（对方公钥格式错误）
            ///
            /// # 工作原理
            /// ```text
            /// 发送方（我）                    接收方
            ///   生成临时密钥对
            ///   (eph_priv, eph_pub)
            ///         │
            ///   ECDH(eph_priv, peer_pub)     ECDH(peer_priv, eph_pub)
            ///         │                            │
            ///         └──────── shared_secret ─────┘
            ///                  （双方相同）
            /// ```
            ///
            /// # 与持久模式的区别
            /// | 特性 | 临时模式（ephemeral） | 持久模式（persistent） |
            /// |------|---------------------|----------------------|
            /// | 前向保密 | ✅ 支持 | ❌ 不支持 |
            /// | 需要发送临时公钥 | ✅ 是 | ❌ 否（双方已有固定密钥） |
            /// | 适用场景 | 消息加密、会话密钥 | 固定双方的长期密钥协商 |
            ///
            /// # 安全建议
            /// ⚠️ `shared_secret` 是原始共享秘密，**不应直接用作加密密钥**，
            /// 建议通过 KDF（如 HKDF）派生后使用，或使用 `ecdh_kdf_hkdf256`。
            ///
            /// # 示例
            /// ```javascript
            /// // 发送方：使用接收方的公钥
            /// const recipientPubKey = loadRecipientPublicKey();
            /// const result = p256_ecdh_ephemeral(recipientPubKey);
            ///
            /// if (result) {
            ///     // 将临时公钥发送给接收方
            ///     send(result.ephemeral_public_key);
            ///
            ///     // 通过 KDF 派生加密密钥
            ///     const salt = crypto.getRandomValues(new Uint8Array(16));
            ///     const key  = hkdf_sha256_derive_from_bytes(
            ///         result.shared_secret, salt, 32
            ///     );
            /// }
            ///
            /// // 接收方：使用自己的私钥与收到的临时公钥
            /// const myPrivKey      = await loadPrivateKey();
            /// const ephPubKey      = receiveEphemeralPublicKey();
            /// const sharedSecret   = p256_ecdh_persistent(myPrivKey, ephPubKey);
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _ecdh_ephemeral>](
                peer_public_key: &[u8],
            ) -> Option<EcdhResult> {
                let (ephemeral_public_key, shared_secret) = $impl::ecdh(peer_public_key)?;
                Some(EcdhResult {
                    ephemeral_public_key,
                    shared_secret,
                })
            }

            /// ECDH 持久模式密钥交换
            ///
            /// 使用自己的固定私钥与对方公钥进行 Diffie-Hellman 交换，
            /// 得到双方共享的秘密值。
            ///
            /// # 参数
            /// - `my_private_key`: 己方原始私钥字节
            /// - `peer_public_key`: 对方 SEC1 压缩格式公钥字节
            ///
            /// # 返回
            /// - `Some(Vec<u8>)`: 交换成功，返回原始共享秘密
            /// - `None`: 交换失败（密钥格式错误或无效）
            ///
            /// # 适用场景
            /// - 双方均持有固定长期密钥对（无需前向保密）
            /// - 接收方处理来自发送方临时模式的 ECDH 请求
            /// - 两个固定节点之间建立共享密钥
            ///
            /// # 与临时模式配合使用
            /// ```text
            /// 发送方（临时模式）           接收方（持久模式）
            ///
            /// ecdh_ephemeral(             ecdh_persistent(
            ///   peer_pub_key               my_priv_key,
            /// )                            sender_eph_pub_key
            ///  → eph_pub_key              )
            ///  → shared_secret             → shared_secret（相同）
            /// ```
            ///
            /// # 安全建议
            /// - 返回的是**原始共享秘密**，建议经过 KDF 处理后再用于加密
            /// - 如需同时获得临时公钥和派生密钥，优先使用 `ecdh_kdf_hkdf256`
            ///
            /// # 示例
            /// ```javascript
            /// // 接收方处理发送方的临时 ECDH 请求
            /// const myPrivKey      = await loadPrivateKey();
            /// const senderEphPub   = receiveSenderEphemeralPublicKey();
            ///
            /// const sharedSecret = p256_ecdh_persistent(myPrivKey, senderEphPub);
            ///
            /// if (sharedSecret) {
            ///     // 派生加密密钥
            ///     const salt = receiveSalt();
            ///     const key  = hkdf_sha256_derive_from_bytes(sharedSecret, salt, 32);
            ///
            ///     // 解密数据
            ///     const plaintext = aes256gcm_decrypt_to_bytes(key, encryptedData);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _ecdh_persistent>](
                my_private_key: &[u8],
                peer_public_key: &[u8],
            ) -> Option<Vec<u8>> {
                $impl::ecdh_with_key(my_private_key, peer_public_key)
            }

            /// ECDH 临时模式 + HKDF-SHA256 密钥派生（推荐使用）
            ///
            /// 在一次调用中完成 ECDH 交换和 HKDF-SHA256 密钥派生，
            /// 直接输出可用于加密的派生密钥，是最安全便捷的密钥协商方式。
            ///
            /// # 参数
            /// - `peer_public_key`: 对方 SEC1 压缩格式 ECC 公钥
            /// - `kdf_salt`: HKDF 盐值（建议 16 字节以上随机数据）
            /// - `output_len`: 期望派生的密钥长度（字节）
            ///
            /// # 返回
            /// - `Some(EcdhResult)`: 成功
            ///   - `ephemeral_public_key`: 本地临时公钥（需发送给对方）
            ///   - `shared_secret`: 经 HKDF-SHA256 派生的密钥（可直接用于加密）
            /// - `None`: 失败（公钥无效、`output_len` 为 0 或超过 HKDF 上限 8160 字节）
            ///
            /// # 内部流程
            /// ```text
            /// peer_pub_key
            ///      │
            ///      ▼
            /// ECDH(eph_priv, peer_pub)
            ///      │
            ///      ▼
            /// raw_shared_secret
            ///      │
            ///      ▼
            /// HKDF-SHA256(ikm=raw_secret, salt=kdf_salt, len=output_len)
            ///      │
            ///      ▼
            /// derived_key（可直接用作 AES/ChaCha20 密钥）
            /// ```
            ///
            /// # 与 `ecdh_ephemeral` 的对比
            /// | | `ecdh_ephemeral` | `ecdh_kdf_hkdf256` |
            /// |-|-----------------|-------------------|
            /// | 输出 | 原始共享秘密 | 派生密钥（可直接使用） |
            /// | 需要额外 KDF | ✅ 是 | ❌ 否（已内置） |
            /// | 安全性 | 需手动处理 | **推荐** |
            ///
            /// # 盐值建议
            /// - 发送方生成随机盐值，与 `ephemeral_public_key` 一起发送给接收方
            /// - 盐值无需保密，但必须唯一（每次交换使用新盐）
            ///
            /// # 示例
            /// ```javascript
            /// // ── 发送方 ──────────────────────────────────────────────
            /// const recipientPubKey = loadRecipientPublicKey();
            /// const kdfSalt  = crypto.getRandomValues(new Uint8Array(16));
            ///
            /// const result = p256_ecdh_kdf_hkdf256(
            ///     recipientPubKey,
            ///     kdfSalt,
            ///     32          // 派生 32 字节密钥用于 AES-256
            /// );
            ///
            /// if (result) {
            ///     const encKey     = result.shared_secret; // 直接用于加密！
            ///     const ephPubKey  = result.ephemeral_public_key;
            ///
            ///     // 加密数据
            ///     const ciphertext = aes256gcm_encrypt_from_bytes(encKey, plaintext);
            ///
            ///     // 发送给接收方（ephPubKey + kdfSalt + ciphertext）
            ///     send({ ephPubKey, kdfSalt, ciphertext });
            /// }
            ///
            /// // ── 接收方 ──────────────────────────────────────────────
            /// const { ephPubKey, kdfSalt, ciphertext } = receive();
            /// const myPrivKey = await loadPrivateKey();
            ///
            /// // 接收方使用持久模式重现相同共享秘密
            /// const rawSecret = p256_ecdh_persistent(myPrivKey, ephPubKey);
            ///
            /// if (rawSecret) {
            ///     // 用相同参数执行 HKDF 派生
            ///     const encKey    = hkdf_sha256_derive_from_bytes(rawSecret, kdfSalt, 32);
            ///     const plaintext = aes256gcm_decrypt_to_bytes(encKey, ciphertext);
            /// }
            /// ```
            #[wasm_bindgen]
            pub fn [<$prefix _ecdh_kdf_hkdf256>](
                peer_public_key: &[u8],
                kdf_salt: &[u8],
                output_len: usize,
            ) -> Option<EcdhResult> {
                let (ephemeral_public_key, shared_secret) =
                    $impl::ecdh_kdf_hkdf256(peer_public_key, kdf_salt, output_len)?;
                Some(EcdhResult {
                    ephemeral_public_key,
                    shared_secret,
                })
            }
        }
    };
}


/// CodeDesc 的 WASM 暴露结构体
#[wasm_bindgen]
pub struct CodeDescResult {
    gen_ts: u64,
    code_valid_duration: u32,
    use_max_duration: u32,
    max_uses: u16,
    product_id: u32,
    prebind: u32,
}

#[wasm_bindgen]
impl CodeDescResult {
    #[wasm_bindgen(getter)]
    pub fn gen_ts(&self) -> u64 { self.gen_ts }

    #[wasm_bindgen(getter)]
    pub fn code_valid_duration(&self) -> u32 { self.code_valid_duration }

    #[wasm_bindgen(getter)]
    pub fn use_max_duration(&self) -> u32 { self.use_max_duration }

    #[wasm_bindgen(getter)]
    pub fn max_uses(&self) -> u16 { self.max_uses }

    #[wasm_bindgen(getter)]
    pub fn product_id(&self) -> u32 { self.product_id }

    #[wasm_bindgen(getter)]
    pub fn prebind(&self) -> u32 { self.prebind }
}

impl From<CodeDesc> for CodeDescResult {
    fn from(d: CodeDesc) -> Self {
        Self {
            gen_ts: d.gen_ts,
            code_valid_duration: d.code_valid_duration,
            use_max_duration: d.use_max_duration,
            max_uses: d.max_uses,
            product_id: d.product_id,
            prebind: d.prebind,
        }
    }
}



/*
/////////////
/// ECC 密钥对结构体
/////////////
*/

/// P-256 密钥对
#[wasm_bindgen]
pub struct P256KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl P256KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/// secp256k1 密钥对
#[wasm_bindgen]
pub struct Secp256k1KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl Secp256k1KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/// P-384 密钥对
#[wasm_bindgen]
pub struct P384KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl P384KeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/// ECDH 结果（包含临时公钥和共享密钥/派生密钥）
#[wasm_bindgen]
pub struct EcdhResult {
    ephemeral_public_key: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl EcdhResult {
    #[wasm_bindgen(getter)]
    pub fn ephemeral_public_key(&self) -> Vec<u8> {
        self.ephemeral_public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}


/*
/////////////
Encoder
命名规则：{algorithm}_encode_from_{input} -> String
          {algorithm}_decode_to_{output}
/////////////
*/

impl_encoder!(base64, Base64);
impl_encoder!(base85, Base85);
impl_encoder!(base91, Base91);


/*
/////////////
Compressor
命名规则：{algorithm}_compress_from_{input}   -> Option<Vec<u8>>
          {algorithm}_decompress_to_{output}
/////////////
*/

impl_compressor!(zstd, Zstd);
impl_compressor!(lz4, Lz4);
impl_compressor!(gzip, Gzip);


/*
/////////////
Hasher
命名规则：{algorithm}_digest_from_{input}          -> String  (hex)
          {algorithm}_digest_raw_from_{input}      -> Vec<u8> (raw bytes)
/////////////
*/

impl_hasher!(sha256, Sha256);
impl_hasher!(sha512, Sha512);
impl_hasher!(sha512_256, Sha512_256);
impl_hasher!(blake3, Blake3);


/*
/////////////
Cipher
命名规则：{algorithm}_encrypt_from_{input}  -> Option<Vec<u8>>
          {algorithm}_decrypt_to_{output}   -> Option<...>
aead系列默认随机nonce。nonce与tag附加在密文上
/////////////
*/

impl_cipher!(aes128gcm, Aes128Gcm);
impl_cipher!(aes256gcm, Aes256Gcm);
impl_cipher!(aes128gcmsiv, Aes128GcmSiv);
impl_cipher!(aes256gcmsiv, Aes256GcmSiv);
impl_cipher!(chacha20poly1305, ChaCha20Poly1305);
impl_cipher!(xchacha20poly1305, XChaCha20Poly1305);


/*
/////////////
AsymmetricCipher
命名规则：{algorithm}_generate_keypair
          {algorithm}_encrypt_from_{input}   -> Option<Vec<u8>>
          {algorithm}_decrypt_to_{output}    -> Option<...>
          {algorithm}_sign_from_{input}      -> Option<Vec<u8>>
          {algorithm}_verify_from_{input}    -> bool
使用OAEP，PSS
/////////////
*/

impl_rsa!(Rsa2048, rsa2048, Rsa2048KeyPair);
impl_rsa!(Rsa4096, rsa4096, Rsa4096KeyPair);


/*
/////////////
Code - 激活码
命名规则：code_{version}_generate          （生成）
          code_{version}_pre_parse         （预解析，修饰词前置）
          code_{version}_verify            （仅验证，返回 bool）
          code_{version}_verify_parse      （验证并解析，动词并列）
/////////////
*/

/// V1
#[wasm_bindgen]
pub fn code_v1_generate(
    key: &[u8],
    product_id: u32,
    code_valid_duration: u32,
    use_max_duration: u32,
    max_uses: u16,
    prebind: Option<u32>,
) -> Option<String> {
    V1::generate(key, product_id, code_valid_duration, use_max_duration, max_uses, prebind)
}

#[wasm_bindgen]
pub fn code_v1_pre_parse(code: &str) -> Option<CodeDescResult> {
    V1::parse_pre(code).map(CodeDescResult::from)
}

#[wasm_bindgen]
pub fn code_v1_verify(
    key: &[u8],
    code: &str,
    product_id: u32,
    prebind: Option<u32>,
) -> bool {
    V1::verify(key, code, product_id, prebind)
}

#[wasm_bindgen]
pub fn code_v1_verify_parse(
    key: &[u8],
    code: &str,
    product_id: u32,
    prebind: Option<u32>,
) -> Option<CodeDescResult> {
    V1::verify_and_parse(key, code, product_id, prebind).map(CodeDescResult::from)
}

/// V2
#[wasm_bindgen]
pub fn code_v2_generate(
    key: &[u8],
    product_id: u32,
    code_valid_duration: u32,
    use_max_duration: u32,
    max_uses: u16,
    prebind: Option<u32>,
) -> Option<String> {
    V2::generate(key, product_id, code_valid_duration, use_max_duration, max_uses, prebind)
}

#[wasm_bindgen]
pub fn code_v2_verify(
    key: &[u8],
    code: &str,
    product_id: u32,
    prebind: Option<u32>,
) -> bool {
    V2::verify(key, code, product_id, prebind)
}

#[wasm_bindgen]
pub fn code_v2_verify_parse(
    key: &[u8],
    code: &str,
    product_id: u32,
    prebind: Option<u32>,
) -> Option<CodeDescResult> {
    V2::verify_and_parse(key, code, product_id, prebind).map(CodeDescResult::from)
}

#[wasm_bindgen]
pub fn rsa_check_pubkey(bytes: &[u8]) -> bool {
    check_pubkey(bytes)
}


/*
/////////////
Kdf - 密钥派生函数
命名规则：{algorithm}_derive_from_{input}         -> Option<Vec<u8>>
          {algorithm}_derive_hex_from_{input}     -> Option<String>

参数说明：
  - password: 用户密码或主密钥
  - salt: 盐值（推荐 16+ 字节随机数据）
  - output_len: 期望密钥长度（默认 32 字节）

安全建议：
  - PBKDF2: 兼容性优先，移动端友好
  - Argon2: 最高安全性，抗 GPU/ASIC 攻击
  - scrypt: 内存硬度，适合资源受限场景
  - HKDF: 仅用于高熵密钥扩展（不适合用户密码）
/////////////
*/

// ── PBKDF2 变体 ──────────────────────────────────────────────────────────────
impl_kdf!(pbkdf2_sha256, Pbkdf2HmacSha256, 32);
impl_kdf!(pbkdf2_sha256_high, Pbkdf2HmacSha256High, 32);
impl_kdf!(pbkdf2_sha512, Pbkdf2HmacSha512, 32);

// ── Argon2 变体 ──────────────────────────────────────────────────────────────
impl_kdf!(argon2id_default, Argon2idDefault, 32);
impl_kdf!(argon2id_high, Argon2idHigh, 32);
impl_kdf!(argon2i, Argon2i, 32);

// ── scrypt 变体 ──────────────────────────────────────────────────────────────
impl_kdf!(scrypt_default, ScryptDefault, 32);
impl_kdf!(scrypt_high, ScryptHigh, 32);

// ── HKDF 变体 ────────────────────────────────────────────────────────────────
impl_kdf!(hkdf_sha256, HkdfSha256, 32);
impl_kdf!(hkdf_sha512, HkdfSha512, 64);



/*
/////////////
ECC - 椭圆曲线密码学
命名规则：{curve}_generate_keypair                -> {curve}KeyPair
          {curve}_sign_from_{input}               -> Option<Vec<u8>>
          {curve}_verify_from_{input}             -> bool
          {curve}_ecdh_ephemeral                  -> Option<EcdhResult>
          {curve}_ecdh_persistent                 -> Option<Vec<u8>>
          {curve}_ecdh_kdf_hkdf256                -> Option<EcdhResult>

曲线选择建议：
  - P-256：NIST标准，广泛支持，兼容性最佳
  - secp256k1：比特币/以太坊标准，金融领域优先
  - P-384：高安全性需求
/////////////
*/

impl_ecc_cipher!(p256, P256, P256KeyPair);
impl_ecc_cipher!(secp256k1, Secp256k1, Secp256k1KeyPair);
impl_ecc_cipher!(p384, P384, P384KeyPair);
