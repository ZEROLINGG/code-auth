use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::error::Error;
use rand::thread_rng;

/// RSA 加密工具结构体
pub struct RSA;

impl RSA {
    // ==================== PEM 转换 ====================

    /// 将 PEM 格式转换为字节数组
    pub fn pem_to_bytes(pem: &str) -> Result<Vec<u8>, base64::DecodeError> {
        let base64_str: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
            .collect();
        BASE64.decode(&base64_str)
    }

    /// 将字节数组转换为 PEM 格式
    pub fn bytes_to_pem(bytes: &[u8], key_type: &str) -> String {
        let base64_str = BASE64.encode(bytes);
        let lines: Vec<&str> = base64_str
            .as_bytes()
            .chunks(64)
            .filter_map(|chunk| std::str::from_utf8(chunk).ok())
            .collect();
        format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----",
            key_type,
            lines.join("\n"),
            key_type
        )
    }

    // ==================== RSA 操作 ====================

    /// 生成 RSA 密钥对 (2048位)
    pub fn generate_rsa_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey), rsa::Error> {
        // 修改：使用 thread_rng()，它会通过 getrandom 0.2 自动调用浏览器的 crypto API
        let mut rng = thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok((private_key, public_key))
    }

    /// 导出公钥为 PEM 格式 (SPKI)
    pub fn export_public_key_pem(key: &RsaPublicKey) -> Result<String, Box<dyn Error>> {
        Ok(key.to_public_key_pem(LineEnding::LF)?)
    }

    /// 导出私钥为 PEM 格式 (PKCS#8)
    pub fn export_private_key_pem(key: &RsaPrivateKey) -> Result<String, Box<dyn Error>> {
        Ok(key.to_pkcs8_pem(LineEnding::LF)?.to_string())
    }

    /// 从 PEM 导入公钥 (SPKI)
    pub fn import_public_key_pem(pem: &str) -> Result<RsaPublicKey, Box<dyn Error>> {
        Ok(RsaPublicKey::from_public_key_pem(pem)?)
    }

    /// 从 PEM 导入私钥 (PKCS#8)
    pub fn import_private_key_pem(pem: &str) -> Result<RsaPrivateKey, Box<dyn Error>> {
        Ok(RsaPrivateKey::from_pkcs8_pem(pem)?)
    }

    /// 使用公钥加密数据 (RSA-OAEP with SHA-256)
    pub fn encrypt(
        data: impl AsRef<[u8]>,
        public_key_pem: &str,
    ) -> Result<String, Box<dyn Error>> {
        let public_key = Self::import_public_key_pem(public_key_pem)?;
        let padding = Oaep::new::<Sha256>();
        let mut rng = thread_rng(); // 修改：显式获取 RNG

        let encrypted = public_key.encrypt(&mut rng, padding, data.as_ref())?;
        Ok(BASE64.encode(&encrypted))
    }

    /// 解密为字节数组
    pub fn decrypt_to_bytes(
        encrypted_b64: &str,
        private_key_pem: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let private_key = Self::import_private_key_pem(private_key_pem)?;
        let encrypted_data = BASE64.decode(encrypted_b64)?;
        let padding = Oaep::new::<Sha256>(); 

        let decrypted = private_key.decrypt(padding, &encrypted_data)?;
        Ok(decrypted)
    }

    /// 解密为字符串 (UTF-8)
    pub fn decrypt_to_string(
        encrypted_b64: &str,
        private_key_pem: &str,
    ) -> Result<String, Box<dyn Error>> {
        let decrypted = Self::decrypt_to_bytes(encrypted_b64, private_key_pem)?;
        Ok(String::from_utf8(decrypted)?)
    }
}