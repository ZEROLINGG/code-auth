//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_test::*;
use lib::_code::V1;
use lib::_lib_base::{Base64, Base91, Encoder};
use lib::_lib_compress::{Zstd,Compressor};
use lib::_lib_hash::{Blake3, Sha256,Hasher};

wasm_bindgen_test_configure!(run_in_browser);


#[cfg(test)]
#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

#[cfg(test)]
#[wasm_bindgen]
pub fn greet() {
    alert("Hello, wasm!");

    let b64 = Base64::encode("哈哈哈哈");
    alert(format!("Hello, {}!", b64).as_str());
    let b64_decoded = Base64::decode(&b64);
    alert(format!("Hello, {:?}!", b64_decoded).as_str());

    let b91 = Base91::encode("哈哈哈哈");
    alert(format!("Hello, {}!", b91).as_str());
    let b91_decoded = Base91::decode(&b91);
    alert(format!("Hello {:?}!", b91_decoded).as_str());

    let zs = Zstd::compress("哈哈哈哈").unwrap();
    alert(format!("Hello {:?}!", zs).as_str());
    let zs_decoded = Zstd::decompress(&zs);
    alert(format!("Hello {:?}!", zs_decoded).as_str());

    let sha256 = Sha256::digest_hex("哈哈哈哈");
    alert(format!("Hello {:?}!", sha256).as_str());
    let blk3 = Blake3::digest_hex("哈哈哈哈");
    alert(format!("Hello {:?}!", blk3).as_str());

    let p_id = 1234;
    let code_1 = V1::generate(&[0x7Eu8; 32],p_id,360,360,1,None).unwrap();
    alert(format!("Hello {:?}!", code_1).as_str());
    let code_1_p = V1::verify_and_parse(&[0x7Eu8; 32], &*code_1, p_id, None).unwrap();
    alert(format!("Hello {:?}!", code_1_p).as_str());
}
#[wasm_bindgen_test]
fn pass() {
    greet();
}
