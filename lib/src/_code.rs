// src/_code.rs

use crate::aes::{Aes128Gcm, Aes256Gcm, Cipher as _};
use crate::base::{Base91,Encoder as _};


/// 明文描述固定长度（不含版本号）：
/// 8 + 4 + 4 + 2 + 4 + 4 = 26
pub const PLAINTEXT_LEN: usize = 26;

/// 激活码版本
pub const CODE_VERSION_V1: u8 = 1;
pub const CODE_VERSION_V2: u8 = 2;

/// 激活码明文描述
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CodeDesc {
    /// 激活码生成时间戳（秒级）
    pub gen_ts: u64,
    /// 激活码有效期时长（秒）
    pub code_valid_duration: u32,
    /// 激活后最多可用时长（秒）
    pub use_max_duration: u32,
    /// 最大可用次数
    pub max_uses: u16,
    /// 产品 id
    pub product_id: u32,
    /// 预绑定数据（0 表示不绑定）
    pub prebind: u32,
}

impl CodeDesc {
    /// 序列化为明文描述（Big-Endian）
    #[inline]
    pub fn to_plaintext_bytes(&self) -> [u8; PLAINTEXT_LEN] {
        let mut out = [0u8; PLAINTEXT_LEN];
        let mut off = 0usize;

        out[off..off + 8].copy_from_slice(&self.gen_ts.to_be_bytes());
        off += 8;
        out[off..off + 4].copy_from_slice(&self.code_valid_duration.to_be_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.use_max_duration.to_be_bytes());
        off += 4;
        out[off..off + 2].copy_from_slice(&self.max_uses.to_be_bytes());
        off += 2;
        out[off..off + 4].copy_from_slice(&self.product_id.to_be_bytes());
        off += 4;
        out[off..off + 4].copy_from_slice(&self.prebind.to_be_bytes());

        out
    }

    /// 从明文字节反序列化
    #[inline]
    pub fn from_plaintext_bytes(bytes: &[u8; PLAINTEXT_LEN]) -> Option<Self> {
        let mut off = 0usize;

        let gen_ts = u64::from_be_bytes(bytes[off..off + 8].try_into().ok()?);
        off += 8;
        let code_valid_duration = u32::from_be_bytes(bytes[off..off + 4].try_into().ok()?);
        off += 4;
        let use_max_duration = u32::from_be_bytes(bytes[off..off + 4].try_into().ok()?);
        off += 4;
        let max_uses = u16::from_be_bytes(bytes[off..off + 2].try_into().ok()?);
        off += 2;
        let product_id = u32::from_be_bytes(bytes[off..off + 4].try_into().ok()?);
        off += 4;
        let prebind = u32::from_be_bytes(bytes[off..off + 4].try_into().ok()?);

        Some(Self {
            gen_ts,
            code_valid_duration,
            use_max_duration,
            max_uses,
            product_id,
            prebind,
        })
    }
}

// ====================== 生成函数 ======================

/// 生成激活码 v1
pub fn _generate_code_v1(key: &[u8], desc: CodeDesc) -> Option<String> {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};

    let _ = desc
        .gen_ts
        .checked_add(desc.code_valid_duration as u64)?
        .checked_add(desc.use_max_duration as u64)?;

    let plaintext = desc.to_plaintext_bytes();
    let mut a = [0u8; 16];
    OsRng.fill_bytes(&mut a);

    let mut payload = Vec::with_capacity(PLAINTEXT_LEN + 16);
    payload.extend_from_slice(&plaintext);
    payload.extend_from_slice(&a);

    let encrypted = match key.len() {
        16 => Aes128Gcm::encrypt(key, payload)?,
        32 => Aes256Gcm::encrypt(key, payload)?,
        _ => return None,
    };

    let mut raw = Vec::with_capacity(1 + PLAINTEXT_LEN + encrypted.len());
    raw.push(CODE_VERSION_V1);
    raw.extend_from_slice(&plaintext);
    raw.extend_from_slice(&encrypted);

    Some(Base91::encode(raw))
}

/// 生成激活码 v2
pub fn _generate_code_v2(key: &[u8], desc: CodeDesc) -> Option<String> {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};

    let _ = desc
        .gen_ts
        .checked_add(desc.code_valid_duration as u64)?
        .checked_add(desc.use_max_duration as u64)?;

    let plaintext = desc.to_plaintext_bytes();
    let mut a = [0u8; 16];
    OsRng.fill_bytes(&mut a);

    let mut payload = Vec::with_capacity(16 + PLAINTEXT_LEN);
    payload.extend_from_slice(&a);
    payload.extend_from_slice(&plaintext);

    let encrypted = match key.len() {
        16 => Aes128Gcm::encrypt(key, payload)?,
        32 => Aes256Gcm::encrypt(key, payload)?,
        _ => return None,
    };

    let mut raw = Vec::with_capacity(1 + encrypted.len());
    raw.push(CODE_VERSION_V2);
    raw.extend_from_slice(&encrypted);

    Some(Base91::encode(raw))
}

// ====================== 内部验证解析函数 ======================

fn _verify_and_parse_v1(
    code: &str,
    key: &[u8],
    product_id: u32,
    prebind: Option<u32>,
) -> Option<CodeDesc> {
    let raw = Base91::decode(code)?;

    if raw.len() < 1 + PLAINTEXT_LEN + 32 {
        return None;
    }
    if raw[0] != CODE_VERSION_V1 {
        return None;
    }

    let plaintext_bytes: [u8; PLAINTEXT_LEN] = raw[1..1 + PLAINTEXT_LEN].try_into().ok()?;
    let desc = CodeDesc::from_plaintext_bytes(&plaintext_bytes)?;

    if desc.product_id != product_id {
        return None;
    }
    if desc.prebind != 0 && desc.prebind != prebind.unwrap_or(0) {
        return None;
    }

    let encrypted = &raw[1 + PLAINTEXT_LEN..];
    let decrypted = match key.len() {
        16 => Aes128Gcm::decrypt(key, encrypted),
        32 => Aes256Gcm::decrypt(key, encrypted),
        _ => return None,
    }?;

    if decrypted.len() != PLAINTEXT_LEN + 16 {
        return None;
    }

    if &decrypted[0..PLAINTEXT_LEN] != plaintext_bytes.as_slice() {
        return None;
    }

    let now = CodeTime::now()?;
    let expiration = CodeTime::add(desc.gen_ts, desc.code_valid_duration as u64)?;

    if now > expiration {
        return None;
    }

    Some(desc)
}

fn _verify_and_parse_v2(
    code: &str,
    key: &[u8],
    product_id: u32,
    prebind: Option<u32>,
) -> Option<CodeDesc> {
    let raw = Base91::decode(code)?;

    if raw.len() < 2 {
        return None;
    }
    if raw[0] != CODE_VERSION_V2 {
        return None;
    }

    let encrypted = &raw[1..];
    let decrypted = match key.len() {
        16 => Aes128Gcm::decrypt(key, encrypted),
        32 => Aes256Gcm::decrypt(key, encrypted),
        _ => return None,
    }?;

    if decrypted.len() != 16 + PLAINTEXT_LEN {
        return None;
    }

    let plaintext_bytes: [u8; PLAINTEXT_LEN] =
        decrypted[16..16 + PLAINTEXT_LEN].try_into().ok()?;
    let desc = CodeDesc::from_plaintext_bytes(&plaintext_bytes)?;

    if desc.product_id != product_id {
        return None;
    }
    if desc.prebind != 0 && desc.prebind != prebind.unwrap_or(0) {
        return None;
    }

    let now = CodeTime::now()?;
    let expiration = CodeTime::add(desc.gen_ts, desc.code_valid_duration as u64)?;

    if now > expiration {
        return None;
    }

    Some(desc)
}

// ====================== 时间工具 ======================

struct CodeTime;

impl CodeTime {
    /// 非 WASM：使用系统时间（标准实现）
    #[cfg(not(target_arch = "wasm32"))]
    #[inline]
    pub fn now() -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
    }

    /// WASM：使用 JS 时间
    #[cfg(target_arch = "wasm32")]
    #[inline]
    pub fn now() -> Option<u64> {
        use js_sys::Date;

        Some((Date::now() / 1000.0) as u64)
    }

    /// 安全加法（所有平台通用）
    #[inline]
    pub fn add(a: u64, b: u64) -> Option<u64> {
        a.checked_add(b)
    }
}

// ====================== 服务器使用接口 ======================

pub struct V1;
impl V1 {
    pub fn generate(
        key: &[u8],
        product_id: u32,
        code_valid_duration: u32,
        use_max_duration: u32,
        max_uses: u16,
        prebind: Option<u32>,
    ) -> Option<String> {
        let desc = CodeDesc {
            gen_ts: CodeTime::now()?,
            code_valid_duration,
            use_max_duration,
            max_uses,
            product_id,
            prebind: prebind.unwrap_or(0),
        };
        _generate_code_v1(key, desc)
    }

    pub fn parse_pre(code: &str) -> Option<CodeDesc> {
        let raw = Base91::decode(code)?;
        if raw.len() < 1 + PLAINTEXT_LEN {
            return None;
        }
        if raw[0] != CODE_VERSION_V1 {
            return None;
        }
        let plaintext_bytes: [u8; PLAINTEXT_LEN] = raw[1..1 + PLAINTEXT_LEN].try_into().ok()?;
        CodeDesc::from_plaintext_bytes(&plaintext_bytes)
    }

    pub fn verify(
        key: &[u8],
        code: &str,
        product_id: u32,
        prebind: Option<u32>,
    ) -> bool {
        Self::verify_and_parse(key, code, product_id, prebind).is_some()
    }

    /// 验证激活码并返回明细信息
    pub fn verify_and_parse(
        key: &[u8],
        code: &str,
        product_id: u32,
        prebind: Option<u32>,
    ) -> Option<CodeDesc> {
        _verify_and_parse_v1(code, key, product_id, prebind)
    }
}

pub struct V2;
impl V2 {
    pub fn generate(
        key: &[u8],
        product_id: u32,
        code_valid_duration: u32,
        use_max_duration: u32,
        max_uses: u16,
        prebind: Option<u32>,
    ) -> Option<String> {
        let desc = CodeDesc {
            gen_ts: CodeTime::now()?,
            code_valid_duration,
            use_max_duration,
            max_uses,
            product_id,
            prebind: prebind.unwrap_or(0),
        };
        _generate_code_v2(key, desc)
    }

    pub fn verify(
        key: &[u8],
        code: &str,
        product_id: u32,
        prebind: Option<u32>,
    ) -> bool {
        Self::verify_and_parse(key, code, product_id, prebind).is_some()
    }

    /// 验证激活码并返回明细信息
    pub fn verify_and_parse(
        key: &[u8],
        code: &str,
        product_id: u32,
        prebind: Option<u32>,
    ) -> Option<CodeDesc> {
        _verify_and_parse_v2(code, key, product_id, prebind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}