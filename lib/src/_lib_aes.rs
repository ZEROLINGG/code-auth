//src/_lib_aes.rs

// use aes_gcm::aes;

pub trait Cipher {
    fn encrypt<T: AsRef<[u8]>>(key: &[u8], plaintext: T) -> Option<Vec<u8>>;
    fn decrypt<T: AsRef<[u8]>>(key: &[u8], ciphertext: T) -> Option<Vec<u8>>;
}

// ─── GCM 模式辅助宏（nonce 12 字节前置） ─────────────────────────────────────

/// GCM 加密输出格式：[ nonce (12 B) | ciphertext + tag (plaintext.len() + 16 B) ]
macro_rules! impl_gcm_cipher {
    ($struct:ty, $cipher_type:ty, $key_len:expr) => {
        impl Cipher for $struct {
            fn encrypt<T: AsRef<[u8]>>(key: &[u8], plaintext: T) -> Option<Vec<u8>> {
                use aes_gcm::{
                    aead::{Aead, AeadCore, KeyInit, OsRng},
                    Key,
                };

                if key.len() != $key_len {
                    return None;
                }

                let key = Key::<$cipher_type>::from_slice(key);
                let cipher = <$cipher_type>::new(key);
                let nonce = <$cipher_type>::generate_nonce(OsRng);

                let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).ok()?;

                let mut output = Vec::with_capacity(12 + ciphertext.len());
                output.extend_from_slice(&nonce);
                output.extend_from_slice(&ciphertext);
                Some(output)
            }

            fn decrypt<T: AsRef<[u8]>>(key: &[u8], ciphertext: T) -> Option<Vec<u8>> {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Key, Nonce,
                };

                let ciphertext = ciphertext.as_ref();
                if key.len() != $key_len || ciphertext.len() < 12 {
                    return None;
                }

                let key = Key::<$cipher_type>::from_slice(key);
                let cipher = <$cipher_type>::new(key);
                let (nonce_bytes, data) = ciphertext.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);

                cipher.decrypt(nonce, data).ok()
            }
        }
    };
}


// ─── 具体实现 ─────────────────────────────────────────────────────────────────

pub struct Aes128Gcm;
impl_gcm_cipher!(Aes128Gcm, aes_gcm::Aes128Gcm, 16);

pub struct Aes256Gcm;
impl_gcm_cipher!(Aes256Gcm, aes_gcm::Aes256Gcm, 32);


// ─── 单元测试 ─────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"Permissions of this weak copyleft license are conditioned on making \
        available source code of licensed files and modifications of those files \
        under the same license (or in certain cases, one of the GNU licenses).";

    fn round_trip<C: Cipher>(label: &str, key: &[u8]) {
        let encrypted = C::encrypt(key, SAMPLE).expect("encrypt failed");
        let decrypted = C::decrypt(key, &encrypted).expect("decrypt failed");
        assert_eq!(decrypted, SAMPLE, "{label}: round-trip mismatch");
        println!(
            "{label}: {} -> {} bytes ({:.1}%)",
            SAMPLE.len(),
            encrypted.len(),
            encrypted.len() as f64 / SAMPLE.len() as f64 * 100.0
        );
    }

    fn wrong_key_returns_none<C: Cipher>(label: &str, key: &[u8], bad_key: &[u8]) {
        let encrypted = C::encrypt(key, SAMPLE).expect("encrypt failed");
        let result = C::decrypt(bad_key, &encrypted);
        assert!(result.is_none(), "{label}: expected None with wrong key");
    }

    // ── AES-128-GCM ──────────────────────────────────────────────────────────
    #[test]
    fn test_aes128gcm_round_trip() {
        round_trip::<Aes128Gcm>("aes-128-gcm", &[0x42u8; 16]);
    }

    #[test]
    fn test_aes128gcm_wrong_key() {
        wrong_key_returns_none::<Aes128Gcm>("aes-128-gcm", &[0x42u8; 16], &[0x00u8; 16]);
    }

    #[test]
    fn test_aes128gcm_invalid_key_len() {
        assert!(Aes128Gcm::encrypt(&[0u8; 10], SAMPLE).is_none());
        assert!(Aes128Gcm::decrypt(&[0u8; 10], &[0u8; 30]).is_none());
    }

    // ── AES-256-GCM ──────────────────────────────────────────────────────────
    #[test]
    fn test_aes256gcm_round_trip() {
        round_trip::<Aes256Gcm>("aes-256-gcm", &[0x7Eu8; 32]);
    }

    #[test]
    fn test_aes256gcm_wrong_key() {
        wrong_key_returns_none::<Aes256Gcm>("aes-256-gcm", &[0x7Eu8; 32], &[0xFFu8; 32]);
    }

    #[test]
    fn test_aes256gcm_invalid_key_len() {
        assert!(Aes256Gcm::encrypt(&[0u8; 16], SAMPLE).is_none()); // 128 位键拒绝 256 位实例
        assert!(Aes256Gcm::decrypt(&[0u8; 16], &[0u8; 50]).is_none());
    }





}