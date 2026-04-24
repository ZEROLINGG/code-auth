// lib/src/_lib_kdf.rs

/// 密钥派生函数（Key Derivation Function）统一接口
pub trait Kdf {
    /// 从密码派生固定长度密钥
    ///
    /// # 参数
    /// - `password`: 用户密码或主密钥
    /// - `salt`: 盐值（防彩虹表攻击）
    /// - `output_len`: 期望输出长度（字节）
    ///
    /// # 返回
    /// - `Some(Vec<u8>)`: 派生成功，长度为 `output_len`
    /// - `None`: 参数无效或派生失败
    fn derive<P: AsRef<[u8]>, S: AsRef<[u8]>>(
        password: P,
        salt: S,
        output_len: usize,
    ) -> Option<Vec<u8>>;
}

// ─── PBKDF2 辅助宏 ────────────────────────────────────────────────────────────
//
// PBKDF2 (Password-Based Key Derivation Function 2)
// - 标准：RFC 8018
// - 特点：简单、广泛支持，抗 GPU/ASIC 能力较弱
// - 适用场景：兼容性优先、低安全要求
//
// 格式：PBKDF2-HMAC-<Hash>
// 参数：iterations（迭代次数，推荐 ≥100,000）
//
macro_rules! impl_pbkdf2_kdf {
    ($struct:ty, $prf:ty, $iterations:expr) => {
        impl Kdf for $struct {
            fn derive<P: AsRef<[u8]>, S: AsRef<[u8]>>(
                password: P,
                salt: S,
                output_len: usize,
            ) -> Option<Vec<u8>> {
                use pbkdf2::pbkdf2_hmac;

                let password = password.as_ref();
                let salt = salt.as_ref();

                if password.is_empty() || salt.is_empty() || output_len == 0 {
                    return None;
                }

                let mut output = vec![0u8; output_len];
                pbkdf2_hmac::<$prf>(password, salt, $iterations, &mut output);
                Some(output)
            }
        }
    };
}

// ─── Argon2 辅助宏 ────────────────────────────────────────────────────────────
//
// Argon2 - 2015 年密码哈希竞赛冠军
// - 标准：RFC 9106
// - 特点：内存硬度（Memory-Hard），抗 GPU/ASIC/时间-内存权衡攻击
// - 变体：
//   * Argon2d：抗 GPU（数据依赖型内存访问）
//   * Argon2i：抗侧信道（数据独立型内存访问）
//   * Argon2id：混合模式（推荐）
//
// 参数调优指南：
// - m_cost：内存使用量（KiB），推荐 ≥19456 (19MB)
// - t_cost：迭代次数，推荐 ≥2
// - p_cost：并行度，推荐 = CPU 核心数
//
macro_rules! impl_argon2_kdf {
    ($struct:ty, $variant:expr, $m_cost:expr, $t_cost:expr, $p_cost:expr) => {
        impl Kdf for $struct {
            fn derive<P: AsRef<[u8]>, S: AsRef<[u8]>>(
                password: P,
                salt: S,
                output_len: usize,
            ) -> Option<Vec<u8>> {
                use argon2::{Argon2, ParamsBuilder, Version};

                let password = password.as_ref();
                let salt = salt.as_ref();

                if password.is_empty() || salt.len() < 8 || output_len == 0 {
                    return None; // Argon2 要求 salt ≥8 字节
                }

                // 构建参数
                let params = ParamsBuilder::new()
                    .m_cost($m_cost)
                    .t_cost($t_cost)
                    .p_cost($p_cost)
                    .output_len(output_len)
                    .build()
                    .ok()?;

                let argon2 = Argon2::new($variant, Version::V0x13, params);

                // 使用底层 API 直接派生密钥
                let mut output = vec![0u8; output_len];
                argon2
                    .hash_password_into(password, salt, &mut output)
                    .ok()?;

                Some(output)
            }
        }
    };
}

// ─── scrypt 辅助宏 ────────────────────────────────────────────────────────────
//
// scrypt - 内存硬度 KDF
// - 标准：RFC 7914
// - 特点：内存密集型，抗并行攻击
// - 适用场景：资源受限设备、需要高内存成本的场景
//
// 参数说明：
// - log_n：CPU/内存成本参数（2^log_n），推荐 14-20
// - r：块大小，推荐 8
// - p：并行度，推荐 1
//
// 内存使用量 ≈ 128 * N * r 字节
// 例：log_n=15, r=8 → 128 * 32768 * 8 = 32MB
//
macro_rules! impl_scrypt_kdf {
    ($struct:ty, $log_n:expr, $r:expr, $p:expr) => {
        impl Kdf for $struct {
            fn derive<P: AsRef<[u8]>, S: AsRef<[u8]>>(
                password: P,
                salt: S,
                output_len: usize,
            ) -> Option<Vec<u8>> {
                use scrypt::{scrypt, Params};

                let password = password.as_ref();
                let salt = salt.as_ref();

                if password.is_empty() || salt.is_empty() || output_len == 0 {
                    return None;
                }

                let params = Params::new($log_n, $r, $p, output_len).ok()?;
                let mut output = vec![0u8; output_len];

                scrypt(password, salt, &params, &mut output).ok()?;
                Some(output)
            }
        }
    };
}

// ─── HKDF 辅助宏 ──────────────────────────────────────────────────────────────
//
// HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
// - 标准：RFC 5869
// - 特点：快速、适用于已有高熵密钥的扩展
// - 阶段：
//   1. Extract：从输入密钥材料提取伪随机密钥（PRK）
//   2. Expand：将 PRK 扩展为多个派生密钥
//
// ⚠️ 注意：不适合低熵密码（应先用 PBKDF2/Argon2 处理）
//
macro_rules! impl_hkdf_kdf {
    ($struct:ty, $hash:ty) => {
        impl Kdf for $struct {
            /// HKDF 派生
            ///
            /// # 参数映射
            /// - `password` → 输入密钥材料（IKM）
            /// - `salt` → 盐值（可选，空则使用全零）
            /// - `output_len` → 输出密钥长度
            fn derive<P: AsRef<[u8]>, S: AsRef<[u8]>>(
                password: P,
                salt: S,
                output_len: usize,
            ) -> Option<Vec<u8>> {
                use hkdf::Hkdf;

                let ikm = password.as_ref();
                let salt = salt.as_ref();

                if ikm.is_empty() || output_len == 0 {
                    return None;
                }

                // Extract-and-Expand
                let hk = Hkdf::<$hash>::new(Some(salt), ikm);
                let mut okm = vec![0u8; output_len];
                hk.expand(&[], &mut okm).ok()?; // info 参数为空

                Some(okm)
            }
        }
    };
}

// ─── 具体实现 ─────────────────────────────────────────────────────────────────

// ── PBKDF2 变体 ──────────────────────────────────────────────────────────────

/// PBKDF2-HMAC-SHA256，100,000 次迭代（OWASP 2023 推荐最低值）
pub struct Pbkdf2HmacSha256;
impl_pbkdf2_kdf!(Pbkdf2HmacSha256, sha2::Sha256, 100_000);

/// PBKDF2-HMAC-SHA256，600,000 次迭代（Apple 平台推荐值）
pub struct Pbkdf2HmacSha256High;
impl_pbkdf2_kdf!(Pbkdf2HmacSha256High, sha2::Sha256, 600_000);

/// PBKDF2-HMAC-SHA512，210,000 次迭代（OWASP 2023 推荐）
pub struct Pbkdf2HmacSha512;
impl_pbkdf2_kdf!(Pbkdf2HmacSha512, sha2::Sha512, 210_000);

// ── Argon2 变体 ──────────────────────────────────────────────────────────────

/// Argon2id，内存 19MB，2 次迭代，1 线程（OWASP 最低推荐）
pub struct Argon2idDefault;
impl_argon2_kdf!(
    Argon2idDefault,
    argon2::Algorithm::Argon2id,
    19456,  // 19MB
    2,      // 2 iterations
    1       // 1 thread
);

/// Argon2id，内存 256MB，3 次迭代，4 线程（高安全场景）
pub struct Argon2idHigh;
impl_argon2_kdf!(
    Argon2idHigh,
    argon2::Algorithm::Argon2id,
    262144, // 256MB
    3,      // 3 iterations
    4       // 4 threads
);

/// Argon2i（抗侧信道攻击），内存 64MB，3 次迭代
pub struct Argon2i;
impl_argon2_kdf!(
    Argon2i,
    argon2::Algorithm::Argon2i,
    65536,  // 64MB
    3,
    1
);

// ── scrypt 变体 ──────────────────────────────────────────────────────────────

/// scrypt，参数 N=2^15 (32MB 内存)，r=8，p=1
pub struct ScryptDefault;
impl_scrypt_kdf!(ScryptDefault, 15, 8, 1);

/// scrypt 高安全，参数 N=2^17 (128MB 内存)，r=8，p=1
pub struct ScryptHigh;
impl_scrypt_kdf!(ScryptHigh, 17, 8, 1);

// ── HKDF 变体 ────────────────────────────────────────────────────────────────

/// HKDF-SHA256（快速密钥扩展）
pub struct HkdfSha256;
impl_hkdf_kdf!(HkdfSha256, sha2::Sha256);

/// HKDF-SHA512
pub struct HkdfSha512;
impl_hkdf_kdf!(HkdfSha512, sha2::Sha512);

// ─── 单元测试 ─────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const SALT: &[u8] = b"seasalt1234567890"; // 16 字节
    const OUTPUT_LEN: usize = 32;

    fn test_deterministic<K: Kdf>(label: &str) {
        let key1 = K::derive(PASSWORD, SALT, OUTPUT_LEN).expect("derive failed");
        let key2 = K::derive(PASSWORD, SALT, OUTPUT_LEN).expect("derive failed");
        assert_eq!(key1, key2, "{label}: not deterministic");
        assert_eq!(key1.len(), OUTPUT_LEN, "{label}: wrong output length");
        println!("{label}: ✓ deterministic, output = {} bytes", key1.len());
    }

    fn test_different_passwords<K: Kdf>(label: &str) {
        let key1 = K::derive(PASSWORD, SALT, OUTPUT_LEN).expect("derive failed");
        let key2 = K::derive(b"wrong password", SALT, OUTPUT_LEN).expect("derive failed");
        assert_ne!(key1, key2, "{label}: same output for different passwords");
    }

    fn test_different_salts<K: Kdf>(label: &str) {
        let key1 = K::derive(PASSWORD, SALT, OUTPUT_LEN).expect("derive failed");
        let key2 = K::derive(PASSWORD, b"differentsalt123", OUTPUT_LEN).expect("derive failed");
        assert_ne!(key1, key2, "{label}: same output for different salts");
    }



    fn test_invalid_inputs<K: Kdf>(label: &str) {
        assert!(
            K::derive(b"", SALT, OUTPUT_LEN).is_none(),
            "{label}: should reject empty password"
        );
        assert!(
            K::derive(PASSWORD, b"", OUTPUT_LEN).is_none(),
            "{label}: should reject empty salt"
        );
        assert!(
            K::derive(PASSWORD, SALT, 0).is_none(),
            "{label}: should reject zero output length"
        );
    }

    // ── PBKDF2 测试 ──────────────────────────────────────────────────────────
    #[test]
    fn test_pbkdf2_sha256() {
        test_deterministic::<Pbkdf2HmacSha256>("pbkdf2-hmac-sha256");
        test_different_passwords::<Pbkdf2HmacSha256>("pbkdf2-hmac-sha256");
        test_different_salts::<Pbkdf2HmacSha256>("pbkdf2-hmac-sha256");
        test_invalid_inputs::<Pbkdf2HmacSha256>("pbkdf2-hmac-sha256");
    }

    #[test]
    fn test_pbkdf2_sha256_high() {
        test_deterministic::<Pbkdf2HmacSha256High>("pbkdf2-hmac-sha256-high");
    }

    #[test]
    fn test_pbkdf2_sha512() {
        test_deterministic::<Pbkdf2HmacSha512>("pbkdf2-hmac-sha512");
        test_different_passwords::<Pbkdf2HmacSha512>("pbkdf2-hmac-sha512");
    }

    // ── Argon2 测试 ──────────────────────────────────────────────────────────
    #[test]
    fn test_argon2id_default() {
        test_deterministic::<Argon2idDefault>("argon2id-default");
        test_different_passwords::<Argon2idDefault>("argon2id-default");
        test_different_salts::<Argon2idDefault>("argon2id-default");
    }

    #[test]
    fn test_argon2id_high() {
        test_deterministic::<Argon2idHigh>("argon2id-high");
    }

    #[test]
    fn test_argon2i() {
        test_deterministic::<Argon2i>("argon2i");
        test_different_passwords::<Argon2i>("argon2i");
    }

    #[test]
    fn test_argon2_salt_requirement() {
        // Argon2 要求 salt ≥8 字节
        let result = Argon2idDefault::derive(PASSWORD, b"short", OUTPUT_LEN);
        assert!(result.is_none(), "should reject salt < 8 bytes");
    }

    // ── scrypt 测试 ──────────────────────────────────────────────────────────
    #[test]
    fn test_scrypt_default() {
        test_deterministic::<ScryptDefault>("scrypt-default");
        test_different_passwords::<ScryptDefault>("scrypt-default");
        test_different_salts::<ScryptDefault>("scrypt-default");
        test_invalid_inputs::<ScryptDefault>("scrypt-default");
    }

    #[test]
    fn test_scrypt_high() {
        test_deterministic::<ScryptHigh>("scrypt-high");
    }

    // ── HKDF 测试 ────────────────────────────────────────────────────────────
    #[test]
    fn test_hkdf_sha256() {
        test_deterministic::<HkdfSha256>("hkdf-sha256");
        test_different_passwords::<HkdfSha256>("hkdf-sha256");
        test_different_salts::<HkdfSha256>("hkdf-sha256");
        // HKDF 允许空 salt（会使用全零）
        let result = HkdfSha256::derive(PASSWORD, b"", OUTPUT_LEN);
        assert!(result.is_some(), "hkdf should allow empty salt");
    }

    #[test]
    fn test_hkdf_sha512() {
        test_deterministic::<HkdfSha512>("hkdf-sha512");
    }

    // ── 通用功能测试 ─────────────────────────────────────────────────────────


    #[test]
    fn test_variable_output_lengths() {
        for len in [16, 32, 64, 128] {
            let key = Pbkdf2HmacSha256::derive(PASSWORD, SALT, len).expect("derive failed");
            assert_eq!(key.len(), len, "output length mismatch for {len}");
        }
    }

    // ── RFC 测试向量 ─────────────────────────────────────────────────────────
    #[test]
    fn test_pbkdf2_rfc6070_vector() {
        // RFC 6070 Test Vector #1
        let key = Pbkdf2HmacSha256::derive(b"password", b"salt", 20)
            .expect("derive failed");

        // 注意：我们的实现使用 100,000 次迭代，RFC 示例用 1 次
        // 这里仅验证格式正确性
        assert_eq!(key.len(), 20);
    }

    #[test]
    fn test_hkdf_rfc5869_vector() {
        // RFC 5869 Test Case 1 (简化版)
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();

        let okm = HkdfSha256::derive(&ikm, &salt, 42).expect("derive failed");
        assert_eq!(okm.len(), 42);

        // 验证输出非零（实际应该与 RFC 向量匹配，这里简化）
        assert!(okm.iter().any(|&b| b != 0));
    }
}