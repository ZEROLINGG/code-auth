use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::thread_rng;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sha2::{Sha256, Digest};

pub struct Aes {
    cipher: Aes256Gcm,
}

impl Aes {
    pub fn new(key_bytes: &[u8]) -> Result<Self, String> {
        if key_bytes.len() != 32 {
            return Err("Key length must be 32 bytes".into());
        }
        let cipher = Aes256Gcm::new_from_slice(key_bytes)
            .map_err(|_| "Failed to create AES cipher".to_string())?;
        Ok(Self { cipher })
    }

    pub fn derive_key<T: AsRef<[u8]>>(input: T) -> [u8; 32] {
        let mut hasher = Sha256::default();
        hasher.update(input.as_ref());
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    pub fn encrypt_to_b64<T: AsRef<[u8]>>(&self, data: T) -> Result<String, String> {
        let bytes = data.as_ref();
        let nonce = Aes256Gcm::generate_nonce(thread_rng());
        let ciphertext = self.cipher.encrypt(&nonce, bytes)
            .map_err(|_| "Encryption failed".to_string())?;

        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&result))
    }

    pub fn decrypt_b64_to_bytes(&self, encoded_data: &str) -> Result<Vec<u8>, String> {
        let encrypted_data = BASE64
            .decode(encoded_data)
            .map_err(|_| "Failed to decode base64 data".to_string())?;

        if encrypted_data.len() < 12 {
            return Err("Encrypted data is too short".into());
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed".to_string())
    }

    pub fn decrypt_b64_to_string(&self, encoded_data: &str) -> Result<String, String> {
        let decrypted_bytes = self.decrypt_b64_to_bytes(encoded_data)?;
        String::from_utf8(decrypted_bytes)
            .map_err(|_| "Decrypted data is not valid UTF-8".to_string())
    }
}
