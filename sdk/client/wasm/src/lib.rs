
// mod a_rsa;
// mod a_aes;
use wasm_bindgen::prelude::*;
// use base64::{engine::general_purpose, Engine as _};
// use serde::Serialize;
// use wasm_bindgen_futures::JsFuture;
// use web_sys::{Request, RequestInit, Response, Headers};
// use serde_json::Value;
// use crate::a_aes::Aes;

use lib::*;
use lib::aes::*;
use lib::compress::Compressor;
use lib::hash::Hasher;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);

}



#[wasm_bindgen]
pub fn greet() {
    let aaa = Aes256Gcm::encrypt(&[0x7Eu8; 32], "WASM").unwrap();
    alert(&format!("Hello from Rust {:?}", compress::Zstd::decompress(&*compress::Zstd::compress(aaa.clone()).unwrap())));
    alert(&format!("Hello from Rust {}", hash::Blake3::digest_hex(aaa.clone())));
    let c = code::V1::generate(&[0x7Eu8; 32], 1234, 360, 360, 1, None).unwrap();

    alert(&format!("{:?}", code::V1::verify_and_parse(&[0x7Eu8; 32],&c,1234,None)));

}

// pub async fn post_json(
//     url: &str,
//     body: &Value,
//     extra_headers: Option<Vec<(String, String)>>,
// ) -> Result<Value, JsValue> {
//     let opts = RequestInit::new();
//
//     opts.set_method("POST");
//
//     let headers = Headers::new()?;
//     headers.set("Content-Type", "application/json")?;
//
//     if let Some(extra) = extra_headers {
//         for (key, value) in extra {
//             headers.set(&key, &value)?;
//         }
//     }
//
//     opts.set_headers(&headers);
//
//     let body_str = serde_json::to_string(body)
//         .map_err(|e| JsValue::from_str(&e.to_string()))?;
//
//     opts.set_body(&JsValue::from_str(&body_str));
//
//     let request = Request::new_with_str_and_init(url, &opts)?;
//
//     let window = web_sys::window()
//         .ok_or_else(|| JsValue::from_str("No window object"))?;
//
//     let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
//     let resp: Response = resp_value.dyn_into()?;
//
//     let json_promise = resp.json()?;
//     let json = JsFuture::from(json_promise).await?;
//     let result: Value = serde_wasm_bindgen::from_value(json)?;
//
//     Ok(result)
// }
//
// #[derive(Serialize)]
// pub struct AuthResult {
//     success: bool,
//     license: Option<String>,
// }
// #[derive(serde::Serialize)]
// pub struct CodeInfo {
//     success: bool,
//     code_expire_at: i64,
//     activation_duration: i64,
//     max_amount: i64,
// }
//
// #[wasm_bindgen]
// pub struct Auth {
//     product_id: String,
//     binding: String,
//     license: Option<String>,
//     server_pub_pem: Option<String>,
//     client_pub_pem: Option<String>,
//     client_pri_pem: Option<String>,
//     client_uuid: Option<String>,
//     aes: Option<Aes>
//
// }
//
// const API_BASE_URL: &str = "https://auth.808050.xyz/api";
// const SERVER_BASE_TS: i64 = 1768276281;
//
// fn auth_result(success: bool, license: Option<String>) -> Result<JsValue, JsValue> {
//     serde_wasm_bindgen::to_value(&AuthResult { success, license })
//         .map_err(|e| JsValue::from_str(&e.to_string()))
// }
//
//
// #[wasm_bindgen]
// impl Auth {
//     #[wasm_bindgen(constructor)]
//     pub fn new(product_id: String, binding: String,license: Option<String>) -> Auth {
//         Auth {
//             product_id,
//             binding,
//             license,
//             server_pub_pem: None,
//             client_pub_pem: None,
//             client_pri_pem: None,
//             client_uuid: None,
//             aes: None,
//         }
//     }
//     /// 检查许可证是否有效
//     pub async fn check(&self) -> Result<JsValue, JsValue> {
//         // 1. 基础校验
//         let license = self.license.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::check] License not found")
//         })?;
//
//         let aes = self.aes.as_ref().ok_or_else(|| {
//             JsValue::from_str("[Auth::check] AES not initialized")
//         })?;
//
//         let client_uuid = self.client_uuid.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::check] Client UUID not initialized")
//         })?;
//
//         let server_pub_pem = self.server_pub_pem.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::check] Server public key not found")
//         })?;
//
//         let client_pri_pem = self.client_pri_pem.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::check] Client private key not found")
//         })?;
//
//         // 2. AES 解密 license
//         let decrypted = aes.decrypt_b64_to_string(&license)
//             .map_err(|e| JsValue::from_str(&format!("License decrypt failed: {}", e)))?;
//
//         // 3. 解析 JSON
//         // [success, activation_uuid, code_expire, use_expire, binding_hash, remaining]
//         let value: Value = serde_json::from_str(&decrypted)
//             .map_err(|e| JsValue::from_str(&format!("Invalid license JSON: {}", e)))?;
//
//         let activation_uuid = value.get(1)
//             .and_then(|v| v.as_str())
//             .ok_or_else(|| JsValue::from_str("Missing activation_uuid"))?;
//
//         let binding_hash = value.get(4)
//             .and_then(|v| v.as_str())
//             .ok_or_else(|| JsValue::from_str("Missing binding_hash"))?;
//
//         // 4. RSA 加密请求数据
//         let enc_activation_uuid = a_rsa::RSA::encrypt(activation_uuid, &server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Encrypt error: {}", e)))?;
//
//         let enc_binding_hash = a_rsa::RSA::encrypt(binding_hash, &server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Encrypt error: {}", e)))?;
//
//         // 5. 构建请求体
//         let request_body = serde_json::json!({
//         "client_uuid": client_uuid,
//         "data_u": enc_activation_uuid,
//         "data_b": enc_binding_hash,
//     });
//
//         // 6. 请求服务器
//         let url = format!("{}/auth/again/reg/code", API_BASE_URL);
//         let response = post_json(&url, &request_body, None).await?;
//
//         let status = response.get("status")
//             .and_then(|v| v.as_str())
//             .unwrap_or("error");
//
//         if status != "ok" {
//             let message = response.get("message")
//                 .and_then(|v| v.as_str())
//                 .unwrap_or("Unknown error");
//             let code = response.get("code")
//                 .and_then(|v| v.as_i64())
//                 .unwrap_or(400);
//             return Err(JsValue::from_str(
//                 &format!("[Auth::check] API error: {} (code: {})", message, code)
//             ));
//         }
//
//         // 7. 解密返回数据
//         let data_array = response.get("data")
//             .and_then(|v| v.as_array())
//             .ok_or_else(|| JsValue::from_str("Missing 'data' in response"))?;
//
//         let mut decrypted_resp = String::new();
//         for item in data_array {
//             if let Some(enc_str) = item.as_str() {
//                 let chunk = a_rsa::RSA::decrypt_to_string(enc_str, &client_pri_pem)
//                     .map_err(|e| JsValue::from_str(&format!("Decrypt error: {}", e)))?;
//                 decrypted_resp.push_str(&chunk);
//             }
//         }
//
//         let result: Value = serde_json::from_str(&decrypted_resp)
//             .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;
//
//         let success = result.get(0)
//             .and_then(|v| v.as_bool())
//             .unwrap_or(false);
//
//         if !success {
//             return auth_result(false, None);
//         }
//
//         // 8. 重新加密并返回新的 license
//         let new_license = aes.encrypt_to_b64(&decrypted_resp)
//             .map_err(|e| JsValue::from_str(&e))?;
//
//         auth_result(true, Some(new_license))
//     }
//
//     /// 激活授权返回许可证
//     pub async fn auth(&mut self, code: String) ->  Result<JsValue, JsValue> {
//         // 返回license
//         if !self.is_initialized() {
//             self.init().await?;
//         }
//         let client_uuid = self.client_uuid.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::auth] Client UUID not initialized")
//         })?;
//
//         let client_pri_pem = self.client_pri_pem.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::auth] Client private key not found")
//         })?;
//
//         let server_pub_pem = self.server_pub_pem.clone().ok_or_else(|| {
//             JsValue::from_str("[Auth::auth] Server public key not found")
//         })?;
//
//         // 构建带时间戳的数据
//         let timestamp = js_sys::Date::now() as i64;
//         let data_c = format!("{}:{}", code, timestamp);
//
//         // 使用服务器公钥加密数据
//         let enc_data_c = a_rsa::RSA::encrypt(&data_c, &server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Encrypt error: {}", e)))?;
//
//         let enc_product_id = a_rsa::RSA::encrypt(&self.product_id, &server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Encrypt error: {}", e)))?;
//
//         let enc_binding = a_rsa::RSA::encrypt(&self.binding, &server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Encrypt error: {}", e)))?;
//
//         // 构建请求体
//         let request_body = serde_json::json!({
//             "client_uuid": client_uuid,
//             "data_c": enc_data_c,
//             "data_i": enc_product_id,
//             "data_b": enc_binding,
//         });
//
//         // 调用服务器核心验证接口
//         let url = format!("{}/auth/reg/code", API_BASE_URL);
//         let response = post_json(&url, &request_body, None).await?;
//
//         // 检查返回状态
//         let status = response.get("status")
//             .and_then(|v| v.as_str())
//             .unwrap_or("error");
//
//         if status != "ok" {
//             let message = response.get("message")
//                 .and_then(|v| v.as_str())
//                 .unwrap_or("Unknown error");
//             let code = response.get("code")
//                 .and_then(|v| v.as_i64())
//                 .unwrap_or(400);
//             return Err(JsValue::from_str(&format!("[Auth::auth] API error: {} (code: {})", message, code)));
//         }
//
//         // 解密返回数据
//         let data_array = response.get("data")
//             .and_then(|v| v.as_array())
//             .ok_or_else(|| JsValue::from_str("Missing 'data' in response"))?;
//
//         let mut decrypted = String::new();
//         for item in data_array {
//             if let Some(enc_str) = item.as_str() {
//                 let chunk = a_rsa::RSA::decrypt_to_string(enc_str, &client_pri_pem)
//                     .map_err(|e| JsValue::from_str(&format!("Decrypt error: {}", e)))?;
//                 decrypted.push_str(&chunk);
//             }
//         }
//
//         // 返回解析后的 JSON 字符串
//         // [true,"522dd1d1-c4e7-4307-a941-530ef4e505f7",31658502,315482535,"1eddeb9444fa9f65dfcac9958d1cef158a7808a00ff76fd6962320d9da26fe0b",4]
//         let value: Value = serde_json::from_str(&decrypted)
//             .map_err(|e| JsValue::from_str(&format!("Invalid JSON: {}", e)))?;
//
//         let success = value
//             .get(0)
//             .and_then(|v| v.as_bool())
//             .unwrap_or(false);
//
//         if !success {
//             return auth_result(false, None);
//         }
//
//         let aes = self.aes.as_ref().ok_or_else(|| {
//             JsValue::from_str("AES not initialized")
//         })?;
//         auth_result(
//             true,
//             Some(aes.encrypt_to_b64(&decrypted)
//                 .map_err(|e| JsValue::from_str(&e))?
//             ),
//         )
//
//     }
//
//     /// 获取客户端UUID
//     fn client_uuid(&self) -> Option<String> {
//         self.client_uuid.clone()
//     }
//
//     /// 检查是否已初始化
//     #[wasm_bindgen(getter)]
//     pub fn is_initialized(&self) -> bool {
//         self.client_uuid.is_some() && self.server_pub_pem.is_some()
//     }
//
//     /// 初始化
//     pub async fn init(&mut self) -> Result<(), JsValue> {
//         // 1. 生成客户端 RSA 密钥对 (2048位)
//         let (client_pri_key, client_pub_key) = a_rsa::RSA::generate_rsa_key_pair()
//             .map_err(|e| JsValue::from_str(&format!("Failed to generate RSA key pair: {}", e)))?;
//
//         // 2. 导出为 PEM 格式
//         let client_pub_pem = a_rsa::RSA::export_public_key_pem(&client_pub_key)
//             .map_err(|e| JsValue::from_str(&format!("Failed to export public key: {}", e)))?;
//         let client_pri_pem = a_rsa::RSA::export_private_key_pem(&client_pri_key)
//             .map_err(|e| JsValue::from_str(&format!("Failed to export private key: {}", e)))?;
//
//         // 3. 构建请求体
//         let request_body = serde_json::json!({
//             "client_pub_key_pem": client_pub_pem
//         });
//
//         // 4. 发送密钥交换请求
//         let url = format!("{}/pub/key/exc", API_BASE_URL);
//         let response = post_json(&url, &request_body, None).await?;
//
//         // 5. 检查响应状态 - 根据服务器格式
//         // 成功: { "status": "ok", "client_uuid": "...", "server_pub_key_pem": "..." }
//         // 失败: { "status": "error", "message": "...", "code": 400 }
//
//         let status = response.get("status")
//             .and_then(|v| v.as_str())
//             .unwrap_or("error");
//
//         if status != "ok" {
//             let message = response.get("message")
//                 .and_then(|v| v.as_str())
//                 .unwrap_or("Unknown error");
//             let code = response.get("code")
//                 .and_then(|v| v.as_i64())
//                 .unwrap_or(400);
//             return Err(JsValue::from_str(&format!("[Auth::init] API error: {} (code: {})", message, code)));
//         }
//
//
//         // 6. 解析响应数据
//         let client_uuid = response.get("client_uuid")
//             .and_then(|v| v.as_str())
//             .ok_or_else(|| JsValue::from_str("Missing 'client_uuid' in response"))?
//             .to_string();
//
//         let server_pub_pem = response.get("server_pub_key_pem")
//             .and_then(|v| v.as_str())
//             .ok_or_else(|| JsValue::from_str("Missing 'server_pub_key_pem' in response"))?
//             .to_string();
//
//
//         // 7. 验证服务器公钥格式
//         a_rsa::RSA::import_public_key_pem(&server_pub_pem)
//             .map_err(|e| JsValue::from_str(&format!("Invalid server public key: {}", e)))?;
//
//         // 8. 保存所有密钥信息
//         self.server_pub_pem = Some(server_pub_pem);
//         self.client_pub_pem = Some(client_pub_pem);
//         self.client_pri_pem = Some(client_pri_pem);
//         self.client_uuid = Some(client_uuid.clone());
//
//         self.init_aes()?;
//         Ok(())
//     }
//
//     fn init_aes(&mut self) -> Result<(), JsValue> {
//         if self.aes.is_none() {
//             let key1 = Aes::derive_key(&self.product_id);
//             let key2 = Aes::derive_key(&self.binding);
//             let mut key = [0u8; 64];
//             key[..32].copy_from_slice(&key1);
//             key[32..].copy_from_slice(&key2);
//             let key = Aes::derive_key(&key);
//             let aes = Aes::new(&key)
//                 .map_err(|e| JsValue::from_str(&format!("AES init failed: {}", e)))?;
//             self.aes = Some(aes);
//         }
//         Ok(())
//     }
//
//     /// 解析激活码信息，返回 code 元信息
//     pub fn info(&mut self, code: String) -> Result<JsValue, JsValue> {
//         let mut result = CodeInfo {
//             success: false,
//             code_expire_at: 0,
//             activation_duration: 0,
//             max_amount: 0,
//         };
//         if let Ok(raw) = general_purpose::STANDARD.decode(&code) {
//             if raw.len() >= 2 {
//                 let cipher_len = ((raw[0] as usize) << 8) | raw[1] as usize;
//                 if raw.len() >= 2 + cipher_len {
//                     let suffix = &raw[2 + cipher_len..];
//                     if let Ok(suffix_str) = std::str::from_utf8(suffix) {
//                         if suffix_str.starts_with(':') {
//                             let parts: Vec<&str> = suffix_str.split(':').collect();
//                             if parts.len() == 4 && parts[0] == "" {
//                                 if let (Ok(code_expire_at), Ok(activation_duration), Ok(max_amount)) = (
//                                     parts[1].parse::<i64>(),
//                                     parts[2].parse::<i64>(),
//                                     parts[3].parse::<i64>(),
//                                 ) {
//                                     let real_ts_ms = (code_expire_at + SERVER_BASE_TS) * 1000;
//                                     result = CodeInfo {
//                                         success: true,
//                                         code_expire_at: real_ts_ms,
//                                         activation_duration,
//                                         max_amount,
//                                     };
//                                 }
//                             }
//                         }
//                     }
//                 }
//             }
//         }
//         serde_wasm_bindgen::to_value(&result)
//             .map_err(|e| JsValue::from_str(&e.to_string()))
//     }
//
//
//
//
// }