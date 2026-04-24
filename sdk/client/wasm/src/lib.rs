// sdk/client/wasm/src/lib.rs

use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response, Headers};
use serde_json::Value;

use lib::base::{Base91,Base85,Encoder};
use lib::{code, kdf};
use lib::aead::{Aes256Gcm, Aes256GcmSiv, Cipher};
use lib::kdf::Kdf;
use lib::rsa::{AsymmetricCipher, Rsa2048};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;


// sdk/client/wasm/src/lib.rs

const SERVICE: &str = "auth-1.0.1";


pub async fn post_json(
    url: &str,
    body: &Value,
    extra_headers: Option<Vec<(String, String)>>,
) -> Result<Value, String> {
    let opts = RequestInit::new();
    opts.set_method("POST");

    let headers = Headers::new()
        .map_err(|_| "Failed to create headers".to_string())?;
    headers.set("Content-Type", "application/json")
        .map_err(|_| "Failed to set Content-Type".to_string())?;

    headers.set("Service", SERVICE)
        .map_err(|_| format!("Failed to set header: {}", "Service"))?;
    if let Some(extra) = extra_headers {
        for (key, value) in extra {
            headers.set(&key, &value)
                .map_err(|_| format!("Failed to set header: {}", key))?;
        }
    }

    opts.set_headers(&headers);

    let body_str = serde_json::to_string(body)
        .map_err(|e| format!("Failed to serialize body: {}", e))?;

    opts.set_body(&JsValue::from_str(&body_str));

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|_| "Failed to create request".to_string())?;

    let window = web_sys::window()
        .ok_or_else(|| "No window object".to_string())?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| "Fetch failed".to_string())?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Invalid response object".to_string())?;

    let json_promise = resp.json()
        .map_err(|_| "Failed to get json promise".to_string())?;

    let json = JsFuture::from(json_promise)
        .await
        .map_err(|_| "Failed to parse JSON".to_string())?;

    let result: Value = serde_wasm_bindgen::from_value(json)
        .map_err(|e| format!("Failed to convert value: {}", e))?;

    Ok(result)
}



/// 从响应中提取 data 字段

fn extract_data(resp: &Value) -> Result<Value, String> {
    let success = resp
        .get("success")
        .and_then(|v| v.as_bool())
        .ok_or("Missing or invalid 'success' field")?;

    if !success {
        let message = resp
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(message.to_string());
    }
    resp.get("data")
        .cloned()
        .ok_or("Missing 'data' field in response".to_string())
}


pub async fn _key_exc(api_base_url: &str) -> Result<([u8; 32], String), String> {
    // ====================== 阶段 1: exc1 ======================
    let (client_pub_der, client_pri_der) = Rsa2048::generate_keypair()
        .ok_or("Failed to generate RSA2048 keypair")?;

    let client_pub_base91 = Base91::encode(&client_pub_der);

    let body1 = serde_json::json!({
        "data": client_pub_base91
    });

    let resp1 = post_json(
        &format!("{}/pub/key/exc1", api_base_url),
        &body1,
        None,
    )
        .await?;

    // 再提取数据
    let data = extract_data(&resp1)?;

    let client_uuid = data
        .get("client_uuid")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'client_uuid' in exc1 response")?
        .to_string();

    let server_pub_base91 = data
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or("Missing server pubkey in exc1 response")?;

    let server_pub_der = Base91::decode(server_pub_base91)
        .ok_or("Failed to base91 decode server public key")?;

    // ====================== 阶段 2: exc2 ======================
    let k1 = rand::random::<[u8; 16]>().to_vec();

    let encrypted_k1 = Rsa2048::encrypt(&server_pub_der, &k1)
        .ok_or("RSA encrypt failed")?;

    let body2 = serde_json::json!({
        "client_uuid": client_uuid,
        "data": Base91::encode(&encrypted_k1)
    });

    let resp2 = post_json(
        &format!("{}/pub/key/exc2", api_base_url),
        &body2,
        None,
    )
        .await?;


    // 再提取数据
    let data = extract_data(&resp2)?;

    let encrypted_session_base91 = data
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'data' in exc2 response")?;

    let encrypted_session = Base91::decode(encrypted_session_base91)
        .ok_or("Failed to base91 decode encrypted session key")?;

    let session_key_vec = Rsa2048::decrypt(&client_pri_der, &encrypted_session)
        .ok_or("Failed to decrypt session key with client private key")?;

    if session_key_vec.len() != 32 {
        return Err(format!(
            "Invalid session key length: expected 32, got {}",
            session_key_vec.len()
        ));
    }

    let mut session_key = [0u8; 32];
    session_key.copy_from_slice(&session_key_vec);

    Ok((session_key, client_uuid))
}



pub async fn _code_v1_parse_pre(code: &str) -> Result<(), String> {
    let _ = code::V1::parse_pre(&code).ok_or(format!("Failed to parse code: {}", code))?;
    Ok(())
}
pub async fn _code_v1_auth(
    code: &str,
    product_id: u32,
    binding: &str,
    parse_pre: bool,
    api_base_url: &str,
    client_uuid: &str,
    session_key: &[u8],
) -> Result<String, String> {
    if parse_pre {
        _code_v1_parse_pre(code).await?;
    }
    if session_key.len() != 32 {
        return Err(format!(
            "Invalid session key length: expected 32, got {}",
            session_key.len()
        ));
    }

    let encrypt = |plaintext: &str| -> Result<String, String> {
        let encrypted = Aes256Gcm::encrypt(session_key, plaintext.as_bytes())
            .ok_or_else(|| format!("AES encrypt failed for: {}", plaintext))?;
        Ok(Base91::encode(&encrypted))
    };

    let now_sec = js_sys::Date::now() / 1000.0;
    let now_sec_str = (now_sec as u64).to_string();

    let data_1 = encrypt(&now_sec_str)?;
    let data_2 = encrypt(code)?;
    let data_3 = encrypt(&product_id.to_string())?;
    let data_4 = encrypt(binding)?;

    let body = serde_json::json!({
        "client_uuid": client_uuid,
        "data_1": data_1,
        "data_2": data_2,
        "data_3": data_3,
        "data_4": data_4,
    });

    let resp = post_json(
        &format!("{}/auth/reg/code/v1", api_base_url),
        &body,
        None,
    )
        .await?;

    let data = extract_data(&resp)?;

    // data 是 base91 编码的 aes256gcm 加密 json 字符串
    let data_str = data
        .as_str()
        .ok_or("Response data is not a string")?;

    let encrypted_bytes = Base91::decode(data_str)
        .ok_or("Failed to base91 decode response data")?;

    let decrypted = Aes256Gcm::decrypt(session_key, &encrypted_bytes)
        .ok_or("Failed to decrypt response data")?;

    let json_str = String::from_utf8(decrypted)
        .map_err(|e| format!("Invalid UTF-8 in response: {}", e))?;

    let key = kdf::Pbkdf2HmacSha256::derive(binding,api_base_url,32)
        .ok_or("Failed to derive key".to_string())?;
    let license = Aes256GcmSiv::encrypt(key.as_slice(), &json_str)
        .ok_or("Failed to encrypt".to_string())?;

    Ok(Base85::encode(license))
}

pub async fn _code_v1_auth_again(
    license_b85: &str,
    binding: &str,
    api_base_url: &str,
    client_uuid: &str,
    session_key: &[u8],
) -> Result<String, String> {
    if session_key.len() != 32 {
        return Err(format!(
            "Invalid session key length: expected 32, got {}",
            session_key.len()
        ));
    }

    let key = kdf::Pbkdf2HmacSha256::derive(binding,api_base_url,32)
        .ok_or("Failed to derive key".to_string())?;
    let license_saved = Base85::decode(license_b85)
        .ok_or("license无效 ".to_string())?;
    let json_str = String::from_utf8(Aes256GcmSiv::decrypt(&key, license_saved)
        .ok_or("Failed to decrypt data")?)
        .map_err(|_| "Failed to decrypt data".to_string())?;


    let prev: Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse json_str: {}", e))?;

    let tag_sig = prev
        .get("tag_sig")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'tag_sig' in json_str")?;

    let product_id = prev
        .get("product_id")
        .and_then(|v| v.as_u64())
        .ok_or("Missing 'product_id' in json_str")?;

    let encrypt = |plaintext: &str| -> Result<String, String> {
        let encrypted = Aes256Gcm::encrypt(session_key, plaintext.as_bytes())
            .ok_or_else(|| format!("AES encrypt failed for: {}", plaintext))?;
        Ok(Base91::encode(&encrypted))
    };

    let now_sec = (js_sys::Date::now() / 1000.0) as u64;

    let data_1 = encrypt(&now_sec.to_string())?;   // 时间戳
    let data_2 = encrypt(tag_sig)?;                  // tag_sig (base85 编码字符串，原样加密)
    let data_3 = encrypt(binding)?;                  // binding
    let data_4 = encrypt(&product_id.to_string())?; // product_id

    let body = serde_json::json!({
        "client_uuid": client_uuid,
        "data_1": data_1,
        "data_2": data_2,
        "data_3": data_3,
        "data_4": data_4,
    });

    let resp = post_json(
        &format!("{}/auth/again/reg/code", api_base_url),
        &body,
        None,
    )
        .await?;

    let data = extract_data(&resp)?;

    let data_str = data
        .as_str()
        .ok_or("Response data is not a string")?;

    let encrypted_bytes = Base91::decode(data_str)
        .ok_or("Failed to base91 decode response data")?;

    let decrypted = Aes256Gcm::decrypt(session_key, &encrypted_bytes)
        .ok_or("Failed to decrypt response data")?;

    let json_str = String::from_utf8(decrypted)
        .map_err(|e| format!("Invalid UTF-8 in response: {}", e))?;

    let license = Aes256GcmSiv::encrypt(key.as_slice(), &json_str)
        .ok_or("Failed to encrypt".to_string())?;

    Ok(Base85::encode(license))
}

/// License 本地预检（不联网，仅返回是否有效）
///
/// 校验内容：
/// - 解密是否成功（binding 是否正确）
/// - product_id 是否匹配
/// - 是否过期（activation_time_point_sec + use_max_duration）
///
/// 不校验 tag_sig（因为没有 productKey）
///
/// 返回: true = 有效, false = 无效
pub async fn _license_precheck(
    license_b85: &str,
    binding: &str,
    api_base_url: &str,
    expected_product_id: u32,
) -> bool {
    let key = match kdf::Pbkdf2HmacSha256::derive(binding, api_base_url, 32) {
        Some(k) => k,
        None => return false,
    };
    let encrypted = match Base85::decode(license_b85) {
        Some(v) => v,
        None => return false,
    };
    let decrypted = match Aes256GcmSiv::decrypt(&key, encrypted) {
        Some(v) => v,
        None => return false,
    };
    let json_str = match String::from_utf8(decrypted) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let v: Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let product_id = match v.get("product_id").and_then(|x| x.as_u64()) {
        Some(id) => id as u32,
        None => return false,
    };
    if product_id != expected_product_id {
        return false;
    }
    let activation_time = match v.get("activation_time_point_sec").and_then(|x| x.as_u64()) {
        Some(t) => t,
        None => return false,
    };
    let duration = match v.get("use_max_duration").and_then(|x| x.as_u64()) {
        Some(d) => d,
        None => return false,
    };
    let now = (js_sys::Date::now() / 1000.0) as u64;
    let expire_time = activation_time.saturating_add(duration);
    if now > expire_time {
        return false;
    }
    true
}

pub async fn _health_check(api_base_url: &str) -> Result<(), String> {
    let url = format!("{}/health", api_base_url);
    let opts = RequestInit::new();
    opts.set_method("GET");

    let headers = Headers::new()
        .map_err(|_| "Failed to create headers".to_string())?;
    headers.set("Content-Type", "application/json")
        .map_err(|_| "Failed to set Content-Type".to_string())?;
    headers.set("Service", SERVICE)
        .map_err(|_| format!("Failed to set header: {}", "Service"))?;
    opts.set_headers(&headers);


    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|_| "Failed to create request".to_string())?;

    let window = web_sys::window()
        .ok_or_else(|| "No window object".to_string())?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| "Fetch failed".to_string())?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Invalid response object".to_string())?;

    let json_promise = resp.json()
        .map_err(|_| "Failed to get json promise".to_string())?;

    let json = JsFuture::from(json_promise)
        .await
        .map_err(|_| "Failed to parse JSON".to_string())?;

    let result: Value = serde_wasm_bindgen::from_value(json)
        .map_err(|e| format!("Failed to convert value: {}", e))?;

    let _data = extract_data(&result)?;

    Ok(())
}

#[derive(Serialize)]
struct InitResult {
    ok: bool,
    err: String,
}

#[derive(Serialize)]
struct AuthOpResult {
    ok: bool,
    license: String,
    err: String,
}

#[wasm_bindgen]
pub struct AuthClient {
    api_base_url: &'static str,
    client_uuid: Option<String>,
    session_key: Option<[u8; 32]>,
    product_id: u32,
    binding: String,
    license: Option<String>,
}

const API_BASE_URL: &str = "https://auth.808050.xyz/api";

#[wasm_bindgen]
impl AuthClient {
    /// 创建实例
    #[wasm_bindgen(constructor)]
    pub fn new(product_id: u32, binding: String, license: Option<String>) -> Result<AuthClient, JsValue> {
        Ok(AuthClient {
            api_base_url: API_BASE_URL,
            client_uuid: None,
            session_key: None,
            product_id,
            binding,
            license,
        })
    }

    /// 进行密钥交换。返回 { ok: bool, err: string }
    #[wasm_bindgen]
    pub async fn init(&mut self) -> JsValue {
        let result = match _key_exc(self.api_base_url).await {
            Ok((key, uuid)) => {
                self.session_key = Some(key);
                self.client_uuid = Some(uuid);
                InitResult {
                    ok: true,
                    err: "".to_string(),
                }
            }
            Err(e) => InitResult {
                ok: false,
                err: e,
            },
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// 检查 license 是否有效，需要init初始化。返回 { ok: bool, license: string, err: string }
    #[wasm_bindgen]
    pub async fn check(&mut self) -> JsValue {
        let op_result: Result<String, String> = async {
            let license_saved = self.license
                .as_ref()
                .ok_or_else(|| "Missing license".to_string())?;

            let client_uuid = self.client_uuid
                .as_ref()
                .ok_or_else(|| "Client not initialized".to_string())?;

            let session_key = self.session_key
                .as_ref()
                .ok_or_else(|| "Session key not initialized".to_string())?;

            _code_v1_auth_again(
                license_saved,
                &self.binding,
                self.api_base_url,
                client_uuid,
                session_key,
            ).await
        }.await;

        let result = match op_result {
            Ok(new_license) => {
                self.license = Some(new_license.clone());
                AuthOpResult {
                    ok: true,
                    license: new_license,
                    err: "".to_string(),
                }
            }
            Err(e) => AuthOpResult {
                ok: false,
                license: "".to_string(),
                err: e,
            },
        };

        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// 认证激活码。使用前需要init进行密钥交换。返回 { ok: bool, license: string, err: string }
    #[wasm_bindgen]
    pub async fn auth(
        &mut self,
        code: String,
    ) -> JsValue {
        let op_result: Result<String, String> = async {
            let client_uuid = self.client_uuid
                .as_ref()
                .ok_or_else(|| "Client not initialized".to_string())?;

            let session_key = self.session_key
                .as_ref()
                .ok_or_else(|| "Session key not initialized".to_string())?;

            _code_v1_auth(
                &code,
                self.product_id,
                &self.binding,
                true,
                self.api_base_url,
                client_uuid,
                session_key,
            ).await
        }.await;

        let result = match op_result {
            Ok(new_license) => {
                self.license = Some(new_license.clone());
                AuthOpResult {
                    ok: true,
                    license: new_license,
                    err: "".to_string(),
                }
            }
            Err(e) => AuthOpResult {
                ok: false,
                license: "".to_string(),
                err: e,
            },
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// 本地预检 License（不联网），无需init进行密钥交换
    #[wasm_bindgen]
    pub async fn precheck_license(&self) -> bool {
        let license = match self.license.as_ref() {
            Some(l) => l,
            None => return false,
        };

        _license_precheck(
            license,
            &self.binding,
            self.api_base_url,
            self.product_id,
        )
            .await
    }

    /// 检查服务器健康状态，无需init进行密钥交换
    /// 返回： { ok: bool, err: "" }
    #[wasm_bindgen]
    pub async fn health(&self) -> JsValue {
        #[derive(Serialize)]
        struct HealthResult {
            ok: bool,
            err: String,
        }
        let result = match _health_check(self.api_base_url).await {
            Ok(_) => HealthResult {
                ok: true,
                err: "".to_string(),
            },
            Err(e) => HealthResult {
                ok: false,
                err: e,
            },
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }
}