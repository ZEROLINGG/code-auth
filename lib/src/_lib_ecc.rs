// lib/src/_lib_ecc.rs

#![allow(unused)]
use crate::hash::{Blake3, Hasher};
use crate::kdf::{HkdfSha256, Kdf};
use k256::{
    ecdh::EphemeralSecret as K256EphemeralSecret,
    ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey},
    EncodedPoint as K256EncodedPoint, PublicKey as K256PublicKey, SecretKey as K256SecretKey,
};
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{Signature, SigningKey, VerifyingKey},
    EncodedPoint, PublicKey, SecretKey,
};
use p384::{
    ecdh::EphemeralSecret as P384EphemeralSecret,
    ecdsa::{Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey},
    EncodedPoint as P384EncodedPoint, PublicKey as P384PublicKey, SecretKey as P384SecretKey,
};
use rand::rngs::OsRng;
use std::marker::PhantomData;

// ─── Trait 定义 ───────────────────────────────────────────────────────────

pub trait EccCipher {
    fn generate_keypair() -> Option<(Vec<u8>, Vec<u8>)>;
    fn sign<T: AsRef<[u8]>>(private_key: &[u8], message: T) -> Option<Vec<u8>>;
    fn verify<T: AsRef<[u8]>>(public_key: &[u8], message: T, signature: &[u8]) -> bool;
    fn ecdh(peer_public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    fn ecdh_with_key(private_key: &[u8], peer_public_key: &[u8]) -> Option<Vec<u8>>;
    fn ecdh_kdf_hkdf256(
        peer_public_key: &[u8],
        kdf_salt: &[u8],
        output_len: usize,
    ) -> Option<(Vec<u8>, Vec<u8>)>;
}

// ─── 私有 Trait：曲线特定操作 ──────────────────────────────────────────────

/// 内部 Trait，封装各曲线的具体实现细节
trait EccCurveOps: Sized {
    /// 关联类型：签名类型
    type Signature;
    /// 关联类型：签名密钥
    type SigningKey;
    /// 关联类型：验证密钥
    type VerifyingKey;
    /// 关联类型：密钥公钥点表示
    type PublicKey;
    /// 关联类型：密钥私钥表示
    type SecretKey;
    /// 关联类型：临时密钥
    type EphemeralSecret;
    /// 关联类型：编码点
    type EncodedPoint;

    // ───── 密钥生成 ─────
    fn generate_secret_key() -> Self::SecretKey;
    fn secret_to_bytes(secret: &Self::SecretKey) -> Vec<u8>;
    fn secret_to_public(secret: &Self::SecretKey) -> Self::PublicKey;
    fn public_to_encoded(public: &Self::PublicKey) -> Vec<u8>;

    // ───── 签名/验证 ─────
    fn signing_key_from_bytes(bytes: &[u8]) -> Option<Self::SigningKey>;
    fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKey>;
    fn sign(key: &Self::SigningKey, digest: &[u8]) -> Self::Signature;
    fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8>;
    fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature>;
    fn verify(key: &Self::VerifyingKey, digest: &[u8], sig: &Self::Signature) -> bool;

    // ───── ECDH ─────
    fn generate_ephemeral() -> Self::EphemeralSecret;
    fn ephemeral_to_public(ephemeral: &Self::EphemeralSecret) -> Self::PublicKey;
    fn ephemeral_to_encoded(ephemeral: &Self::EphemeralSecret) -> Vec<u8>;
    fn public_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey>;
    fn secret_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey>;
    fn ephemeral_diffie_hellman(ephemeral: &Self::EphemeralSecret, peer_public: &Self::PublicKey) -> Vec<u8>;
    fn persistent_diffie_hellman(secret: &Self::SecretKey, peer_public: &Self::PublicKey) -> Vec<u8>;
}

// ─── 通用 EccCipher 实现（使用 PhantomData）────────────────────────────────

/// 通用 ECC 实现
struct EccImpl<T: EccCurveOps> {
    _phantom: PhantomData<T>,
}

impl<T: EccCurveOps + 'static> EccCipher for EccImpl<T> {
    fn generate_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
        let secret = T::generate_secret_key();
        let public = T::secret_to_public(&secret);
        let pub_bytes = T::public_to_encoded(&public);
        let pri_bytes = T::secret_to_bytes(&secret);
        Some((pub_bytes, pri_bytes))
    }

    fn sign<Msg: AsRef<[u8]>>(private_key: &[u8], message: Msg) -> Option<Vec<u8>> {
        let signing_key = T::signing_key_from_bytes(private_key)?;
        let digest = Blake3::digest_vec(message.as_ref());
        let sig = T::sign(&signing_key, &digest);
        Some(T::signature_to_bytes(&sig))
    }

    fn verify<Msg: AsRef<[u8]>>(public_key: &[u8], message: Msg, signature: &[u8]) -> bool {
        let verifying_key = match T::verifying_key_from_bytes(public_key) {
            Some(k) => k,
            None => return false,
        };
        let digest = Blake3::digest_vec(message.as_ref());
        let sig = match T::signature_from_bytes(signature) {
            Some(s) => s,
            None => return false,
        };
        T::verify(&verifying_key, &digest, &sig)
    }

    fn ecdh(peer_public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let peer_pk = T::public_from_bytes(peer_public_key)?;
        let ephemeral = T::generate_ephemeral();
        let our_pub = T::ephemeral_to_encoded(&ephemeral);
        let shared_bytes = T::ephemeral_diffie_hellman(&ephemeral, &peer_pk);
        Some((our_pub, shared_bytes))
    }

    fn ecdh_with_key(private_key: &[u8], peer_public_key: &[u8]) -> Option<Vec<u8>> {
        let secret_key = T::secret_from_bytes(private_key)?;
        let peer_pk = T::public_from_bytes(peer_public_key)?;
        Some(T::persistent_diffie_hellman(&secret_key, &peer_pk))
    }

    fn ecdh_kdf_hkdf256(
        peer_public_key: &[u8],
        kdf_salt: &[u8],
        output_len: usize,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let (our_pub, shared_secret) = Self::ecdh(peer_public_key)?;
        let derived_key = HkdfSha256::derive(&shared_secret, kdf_salt, output_len)?;
        Some((our_pub, derived_key))
    }
}

// ─── 宏：自动实现 EccCurveOps ────────────────────────────────────────────────

/// 为各曲线实现 EccCurveOps trait
/// 使用示例：impl_ecc_curve_ops!(P256CurveOps, p256, ...);
macro_rules! impl_ecc_curve_ops {
    (
        $struct_name:ident,
        $module:ident,
        Sig=$sig_type:ty,
        SigningKey=$sk_type:ty,
        VerifyingKey=$vk_type:ty,
        PublicKey=$pk_type:ty,
        SecretKey=$secret_type:ty,
        EphemeralSecret=$ephemeral_type:ty,
        EncodedPoint=$encoded_type:ty
    ) => {
        struct $struct_name;

        impl EccCurveOps for $struct_name {
            type Signature = $sig_type;
            type SigningKey = $sk_type;
            type VerifyingKey = $vk_type;
            type PublicKey = $pk_type;
            type SecretKey = $secret_type;
            type EphemeralSecret = $ephemeral_type;
            type EncodedPoint = $encoded_type;

            fn generate_secret_key() -> Self::SecretKey {
                <$secret_type>::random(&mut OsRng)
            }

            fn secret_to_bytes(secret: &Self::SecretKey) -> Vec<u8> {
                secret.to_bytes().to_vec()
            }

            fn secret_to_public(secret: &Self::SecretKey) -> Self::PublicKey {
                secret.public_key()
            }

            fn public_to_encoded(public: &Self::PublicKey) -> Vec<u8> {
                <$encoded_type>::from(public).compress().as_bytes().to_vec()
            }

            fn signing_key_from_bytes(bytes: &[u8]) -> Option<Self::SigningKey> {
                <$sk_type>::from_bytes(bytes.into()).ok()
            }

            fn verifying_key_from_bytes(bytes: &[u8]) -> Option<Self::VerifyingKey> {
                <$vk_type>::from_sec1_bytes(bytes).ok()
            }

            fn sign(key: &Self::SigningKey, digest: &[u8]) -> Self::Signature {
                use $module::ecdsa::signature::Signer;
                key.sign(digest)
            }

            fn signature_to_bytes(sig: &Self::Signature) -> Vec<u8> {
                sig.to_bytes().to_vec()
            }

            fn signature_from_bytes(bytes: &[u8]) -> Option<Self::Signature> {
                <$sig_type>::from_bytes(bytes.into()).ok()
            }

            fn verify(key: &Self::VerifyingKey, digest: &[u8], sig: &Self::Signature) -> bool {
                use $module::ecdsa::signature::Verifier;
                key.verify(digest, sig).is_ok()
            }

            fn generate_ephemeral() -> Self::EphemeralSecret {
                <$ephemeral_type>::random(&mut OsRng)
            }

            fn ephemeral_to_public(ephemeral: &Self::EphemeralSecret) -> Self::PublicKey {
                ephemeral.public_key()
            }

            fn ephemeral_to_encoded(ephemeral: &Self::EphemeralSecret) -> Vec<u8> {
                <$encoded_type>::from(ephemeral.public_key())
                    .compress()
                    .as_bytes()
                    .to_vec()
            }

            fn public_from_bytes(bytes: &[u8]) -> Option<Self::PublicKey> {
                <$pk_type>::from_sec1_bytes(bytes).ok()
            }

            fn secret_from_bytes(bytes: &[u8]) -> Option<Self::SecretKey> {
                <$secret_type>::from_slice(bytes).ok()
            }

            fn ephemeral_diffie_hellman(
                ephemeral: &Self::EphemeralSecret,
                peer_public: &Self::PublicKey,
            ) -> Vec<u8> {
                let shared = ephemeral.diffie_hellman(peer_public);
                shared.raw_secret_bytes().to_vec()
            }

            fn persistent_diffie_hellman(
                secret: &Self::SecretKey,
                peer_public: &Self::PublicKey,
            ) -> Vec<u8> {
                let shared = $module::ecdh::diffie_hellman(
                    secret.to_nonzero_scalar(),
                    peer_public.as_affine(),
                );
                shared.raw_secret_bytes().to_vec()
            }
        }
    };
}

// ─── 使用宏生成三个曲线的实现 ─────────────────────────────────────────────

impl_ecc_curve_ops!(
    P256CurveOps,
    p256,
    Sig = Signature,
    SigningKey = SigningKey,
    VerifyingKey = VerifyingKey,
    PublicKey = PublicKey,
    SecretKey = SecretKey,
    EphemeralSecret = EphemeralSecret,
    EncodedPoint = EncodedPoint
);

impl_ecc_curve_ops!(
    Secp256k1CurveOps,
    k256,
    Sig = K256Signature,
    SigningKey = K256SigningKey,
    VerifyingKey = K256VerifyingKey,
    PublicKey = K256PublicKey,
    SecretKey = K256SecretKey,
    EphemeralSecret = K256EphemeralSecret,
    EncodedPoint = K256EncodedPoint
);

impl_ecc_curve_ops!(
    P384CurveOps,
    p384,
    Sig = P384Signature,
    SigningKey = P384SigningKey,
    VerifyingKey = P384VerifyingKey,
    PublicKey = P384PublicKey,
    SecretKey = P384SecretKey,
    EphemeralSecret = P384EphemeralSecret,
    EncodedPoint = P384EncodedPoint
);

// ─── 宏：自动实现 EccCipher trait ──────────────────────────────────────────

/// 为公共 API 结构体实现 EccCipher trait
/// 使用示例：impl_ecc_cipher!(P256, P256CurveOps);
macro_rules! impl_ecc_cipher {
    ($public_struct:ident, $curve_ops:ident) => {
        pub struct $public_struct;

        impl EccCipher for $public_struct {
            fn generate_keypair() -> Option<(Vec<u8>, Vec<u8>)> {
                EccImpl::<$curve_ops>::generate_keypair()
            }

            fn sign<T: AsRef<[u8]>>(private_key: &[u8], message: T) -> Option<Vec<u8>> {
                EccImpl::<$curve_ops>::sign(private_key, message)
            }

            fn verify<T: AsRef<[u8]>>(public_key: &[u8], message: T, signature: &[u8]) -> bool {
                EccImpl::<$curve_ops>::verify(public_key, message, signature)
            }

            fn ecdh(peer_public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                EccImpl::<$curve_ops>::ecdh(peer_public_key)
            }

            fn ecdh_with_key(private_key: &[u8], peer_public_key: &[u8]) -> Option<Vec<u8>> {
                EccImpl::<$curve_ops>::ecdh_with_key(private_key, peer_public_key)
            }

            fn ecdh_kdf_hkdf256(
                peer_public_key: &[u8],
                kdf_salt: &[u8],
                output_len: usize,
            ) -> Option<(Vec<u8>, Vec<u8>)> {
                EccImpl::<$curve_ops>::ecdh_kdf_hkdf256(peer_public_key, kdf_salt, output_len)
            }
        }
    };
}

// ─── 使用宏生成三个公共 API ────────────────────────────────────────────────

impl_ecc_cipher!(P256, P256CurveOps);
impl_ecc_cipher!(Secp256k1, Secp256k1CurveOps);
impl_ecc_cipher!(P384, P384CurveOps);

// ─── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 为单条曲线生成完整的测试套件
    macro_rules! test_curve {
        (
            $curve:ident,
            $test_mod_name:ident,
            pub_size=$pub_size:expr,
            pri_size=$pri_size:expr,
            sig_size=$sig_size:expr,
            shared_size=$shared_size:expr,
            name=$curve_name:expr
        ) => {
            mod $test_mod_name {
                use super::*;

                #[test]
                fn test_generate_keypair() {
                    let (pub_key, pri_key) = $curve::generate_keypair()
                        .expect(&format!("生成 {} 密钥对失败", $curve_name));

                    assert_eq!(
                        pub_key.len(),
                        $pub_size,
                        "{} 公钥应为 {} 字节",
                        $curve_name,
                        $pub_size
                    );
                    assert!(
                        pub_key[0] == 0x02 || pub_key[0] == 0x03,
                        "{} 公钥格式错误",
                        $curve_name
                    );
                    assert_eq!(
                        pri_key.len(),
                        $pri_size,
                        "{} 私钥应为 {} 字节",
                        $curve_name,
                        $pri_size
                    );
                }

                #[test]
                fn test_sign_and_verify() {
                    let (pub_key, pri_key) = $curve::generate_keypair()
                        .expect(&format!("生成 {} 密钥对失败", $curve_name));
                    let message = format!("Hello, {}!", $curve_name).into_bytes();

                    let signature = $curve::sign(&pri_key, &message)
                        .expect(&format!("{} 签名失败", $curve_name));
                    assert_eq!(
                        signature.len(),
                        $sig_size,
                        "{} 签名应为 {} 字节",
                        $curve_name,
                        $sig_size
                    );

                    assert!(
                        $curve::verify(&pub_key, &message, &signature),
                        "{} 签名验证应成功",
                        $curve_name
                    );
                    assert!(
                        !$curve::verify(&pub_key, b"Wrong message", &signature),
                        "{} 对错误消息验证应失败",
                        $curve_name
                    );
                }

                #[test]
                fn test_ecdh() {
                    let (alice_pub, _alice_pri) = $curve::generate_keypair()
                        .expect(&format!("Alice {} 密钥对生成失败", $curve_name));

                    let (bob_ephemeral_pub, bob_shared) =
                        $curve::ecdh(&alice_pub).expect(&format!("Bob {} ECDH 失败", $curve_name));

                    assert_eq!(
                        bob_ephemeral_pub.len(),
                        $pub_size,
                        "{} 临时公钥应为 {} 字节",
                        $curve_name,
                        $pub_size
                    );
                    assert_eq!(
                        bob_shared.len(),
                        $shared_size,
                        "{} 共享密钥应为 {} 字节",
                        $curve_name,
                        $shared_size
                    );
                }

                #[test]
                fn test_ecdh_with_key() {
                    let (alice_pub, alice_pri) = $curve::generate_keypair()
                        .expect(&format!("Alice {} 密钥对失败", $curve_name));
                    let (bob_pub, bob_pri) = $curve::generate_keypair()
                        .expect(&format!("Bob {} 密钥对失败", $curve_name));

                    let alice_shared = $curve::ecdh_with_key(&alice_pri, &bob_pub)
                        .expect(&format!("Alice {} ECDH 失败", $curve_name));

                    let bob_shared = $curve::ecdh_with_key(&bob_pri, &alice_pub)
                        .expect(&format!("Bob {} ECDH 失败", $curve_name));

                    assert_eq!(
                        alice_shared, bob_shared,
                        "{} ECDH 共享密钥应相同",
                        $curve_name
                    );
                    assert_eq!(
                        alice_shared.len(),
                        $shared_size,
                        "{} 共享密钥应为 {} 字节",
                        $curve_name,
                        $shared_size
                    );
                }

                #[test]
                fn test_ecdh_kdf_hkdf256() {
                    let (alice_pub, _) = $curve::generate_keypair()
                        .expect(&format!("Alice {} 密钥对失败", $curve_name));
                    let salt = format!("test_salt_{}", stringify!($test_mod_name)).into_bytes();
                    let output_len = 32;

                    let (ephemeral_pub, derived_key) =
                        $curve::ecdh_kdf_hkdf256(&alice_pub, &salt, output_len)
                            .expect(&format!("{} HKDF 派生失败", $curve_name));

                    assert_eq!(
                        ephemeral_pub.len(),
                        $pub_size,
                        "{} 临时公钥应为 {} 字节",
                        $curve_name,
                        $pub_size
                    );
                    assert_eq!(
                        derived_key.len(),
                        output_len,
                        "{} 派生密钥应为 {} 字节",
                        $curve_name,
                        output_len
                    );
                }
            }
        };
    }

    // ─── 使用宏生成三条曲线的完整测试 ──────────────────────────────────

    test_curve!(
        P256,
        p256_tests,
        pub_size = 33,
        pri_size = 32,
        sig_size = 64,
        shared_size = 32,
        name = "P-256"
    );

    test_curve!(
        Secp256k1,
        secp256k1_tests,
        pub_size = 33,
        pri_size = 32,
        sig_size = 64,
        shared_size = 32,
        name = "secp256k1"
    );

    test_curve!(
        P384,
        p384_tests,
        pub_size = 49,
        pri_size = 48,
        sig_size = 96,
        shared_size = 48,
        name = "P-384"
    );

    // ─── 跨曲线对比测试 ───────────────────────────────────────────────────

    #[test]
    fn test_three_curves_keypair_sizes() {
        // P-256
        let (p256_pub, p256_pri) = P256::generate_keypair().expect("P-256 生成失败");
        assert_eq!(p256_pub.len(), 33);
        assert_eq!(p256_pri.len(), 32);

        // secp256k1
        let (k256_pub, k256_pri) = Secp256k1::generate_keypair().expect("secp256k1 生成失败");
        assert_eq!(k256_pub.len(), 33);
        assert_eq!(k256_pri.len(), 32);

        // P-384
        let (p384_pub, p384_pri) = P384::generate_keypair().expect("P-384 生成失败");
        assert_eq!(p384_pub.len(), 49);
        assert_eq!(p384_pri.len(), 48);
    }

    #[test]
    fn test_three_curves_signature_sizes() {
        let msg = b"test message";

        // P-256 签名
        let (_, p256_pri) = P256::generate_keypair().expect("P-256 生成失败");
        let p256_sig = P256::sign(&p256_pri, msg).expect("P-256 签名失败");
        assert_eq!(p256_sig.len(), 64);

        // secp256k1 签名
        let (_, k256_pri) = Secp256k1::generate_keypair().expect("secp256k1 生成失败");
        let k256_sig = Secp256k1::sign(&k256_pri, msg).expect("secp256k1 签名失败");
        assert_eq!(k256_sig.len(), 64);

        // P-384 签名
        let (_, p384_pri) = P384::generate_keypair().expect("P-384 生成失败");
        let p384_sig = P384::sign(&p384_pri, msg).expect("P-384 签名失败");
        assert_eq!(p384_sig.len(), 96);
    }

    #[test]
    fn test_three_curves_ecdh_shared_key_sizes() {
        // P-256 ECDH
        let (p256_pub, _) = P256::generate_keypair().expect("P-256 生成失败");
        let (_, p256_shared) = P256::ecdh(&p256_pub).expect("P-256 ECDH 失败");
        assert_eq!(p256_shared.len(), 32);

        // secp256k1 ECDH
        let (k256_pub, _) = Secp256k1::generate_keypair().expect("secp256k1 生成失败");
        let (_, k256_shared) = Secp256k1::ecdh(&k256_pub).expect("secp256k1 ECDH 失败");
        assert_eq!(k256_shared.len(), 32);

        // P-384 ECDH
        let (p384_pub, _) = P384::generate_keypair().expect("P-384 生成失败");
        let (_, p384_shared) = P384::ecdh(&p384_pub).expect("P-384 ECDH 失败");
        assert_eq!(p384_shared.len(), 48);
    }

    #[test]
    fn test_p256_persistent_and_ephemeral_ecdh_consistency() {
        // 验证持久化和临时 ECDH 的一致性
        let (pub_a, pri_a) = P256::generate_keypair().expect("Alice 生成失败");
        let (pub_b, pri_b) = P256::generate_keypair().expect("Bob 生成失败");

        // 方式 1：持久化 ECDH
        let shared1 = P256::ecdh_with_key(&pri_a, &pub_b).expect("ECDH with key 失败");

        // 方式 2：如果我们想用 pub_a 和 pri_b 重现相同的交换
        let shared2 = P256::ecdh_with_key(&pri_b, &pub_a).expect("ECDH with key 失败");

        // 两个方向的共享密钥应该相同
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_secp256k1_persistent_and_ephemeral_ecdh_consistency() {
        // 验证持久化和临时 ECDH 的一致性
        let (pub_a, pri_a) = Secp256k1::generate_keypair().expect("Alice 生成失败");
        let (pub_b, pri_b) = Secp256k1::generate_keypair().expect("Bob 生成失败");

        // 方式 1：持久化 ECDH
        let shared1 = Secp256k1::ecdh_with_key(&pri_a, &pub_b).expect("ECDH with key 失败");

        // 方式 2：如果我们想用 pub_a 和 pri_b 重现相同的交换
        let shared2 = Secp256k1::ecdh_with_key(&pri_b, &pub_a).expect("ECDH with key 失败");

        // 两个方向的共享密钥应该相同
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_p384_persistent_and_ephemeral_ecdh_consistency() {
        // 验证持久化和临时 ECDH 的一致性
        let (pub_a, pri_a) = P384::generate_keypair().expect("Alice 生成失败");
        let (pub_b, pri_b) = P384::generate_keypair().expect("Bob 生成失败");

        // 方式 1：持久化 ECDH
        let shared1 = P384::ecdh_with_key(&pri_a, &pub_b).expect("ECDH with key 失败");

        // 方式 2：如果我们想用 pub_a 和 pri_b 重现相同的交换
        let shared2 = P384::ecdh_with_key(&pri_b, &pub_a).expect("ECDH with key 失败");

        // 两个方向的共享密钥应该相同
        assert_eq!(shared1, shared2);
    }
}