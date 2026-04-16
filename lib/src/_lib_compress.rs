
const MAX_COMPRESSION_RATIO: u64 = 1024;
const MAX_DECOMPRESSED_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

pub trait Compressor {
    fn compress<T: AsRef<[u8]>>(input: T) -> Option<Vec<u8>>;
    fn decompress(input: &[u8]) -> Option<Vec<u8>>;
}

// ====================== Lz4 ======================

pub struct Lz4;

impl Compressor for Lz4 {
    fn compress<T: AsRef<[u8]>>(input: T) -> Option<Vec<u8>> {
        Some(lz4_flex::compress_prepend_size(input.as_ref()))
    }

    fn decompress(input: &[u8]) -> Option<Vec<u8>> {
        if input.len() < 4 {
            return None;
        }

        let declared_size =
            u32::from_le_bytes(input[..4].try_into().ok()?) as u64;

        let bomb_limit = (input.len() as u64)
            .saturating_mul(MAX_COMPRESSION_RATIO)
            .min(MAX_DECOMPRESSED_SIZE);

        if declared_size > bomb_limit {
            return None;
        }

        lz4_flex::decompress_size_prepended(input).ok()
    }
}

// ====================== Gzip ======================

pub struct Gzip;

impl Compressor for Gzip {
    fn compress<T: AsRef<[u8]>>(input: T) -> Option<Vec<u8>> {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let input = input.as_ref();
        let cap = input.len() + (input.len() / 10).max(64) + 18;
        let mut encoder = GzEncoder::new(Vec::with_capacity(cap), Compression::default());

        encoder.write_all(input).ok()?;
        encoder.finish().ok()
    }

    fn decompress(input: &[u8]) -> Option<Vec<u8>> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let bomb_limit = (input.len() as u64).saturating_mul(MAX_COMPRESSION_RATIO).min(MAX_DECOMPRESSED_SIZE);

        let estimated_cap = if input.len() >= 4 {
            let isize_bytes: [u8; 4] = input[input.len() - 4..].try_into().ok()?;
            let original_size = u32::from_le_bytes(isize_bytes) as u64;

            if original_size > bomb_limit {
                return None;
            }
            original_size as usize
        } else {
            input.len().saturating_mul(3)
        };

        let mut buf = Vec::with_capacity(estimated_cap);
        let mut limited_reader = GzDecoder::new(input).take(bomb_limit + 1);

        limited_reader.read_to_end(&mut buf).ok()?;

        if buf.len() as u64 > bomb_limit {
            return None;
        }

        Some(buf)
    }
}

// ====================== Zstd ======================

pub struct Zstd;

impl Compressor for Zstd {
    fn compress<T: AsRef<[u8]>>(input: T) -> Option<Vec<u8>> {
        zstd::encode_all(input.as_ref(), 5).ok()
    }

    fn decompress(input: &[u8]) -> Option<Vec<u8>> {
        use std::io::Read;

        let bomb_limit = (input.len() as u64)
            .saturating_mul(MAX_COMPRESSION_RATIO)
            .min(MAX_DECOMPRESSED_SIZE);

        let estimated_cap = zstd::zstd_safe::get_frame_content_size(input)
            .ok()
            .flatten()
            .filter(|&size| size <= bomb_limit)
            .map(|size| size as usize)
            .unwrap_or_else(|| input.len().saturating_mul(3));

        let mut buf = Vec::with_capacity(estimated_cap);
        let decoder = zstd::Decoder::new(input).ok()?;
        let mut limited_reader = decoder.take(bomb_limit + 1);

        limited_reader.read_to_end(&mut buf).ok()?;

        if buf.len() as u64 > bomb_limit {
            return None;
        }

        Some(buf)
    }
}

// ====================== Tests ======================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"\
!function(o,t){''object''==typeof exports&&''object''==typeof module?module.exports=t():''function''==typeof define&&define.amd?define([],t):''object''==typeof exports?exports[''family-aa686e0e9e4d122550f8'']=t():o[''family-aa686e0e9e4d122550f8'']=t()}(window,function(){return function(o){var t={};function q(n){if(t[n])return t[n].exports;var e=t[n]={i:n,l:!1,exports:{}};return o[n].call(e.exports,e,e.exports,q),e.l=!0,e.exports}return q.m=o,q.c=t,q.d=function(o,t,n){q.o(o,t)||Object.defineProperty(o,t,{enumerable:!0,get:n})},q.r=function(o){''undefined''!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(o,Symbol.toStringTag,{value:''Module''}),Object.defineProperty(o,''__esModule'',{value:!0})},q.t=function(o,t){if(1&t&&(o=q(o)),8&t)return o;if(4&t&&''object''==typeof o&&o&&o.__esModule)return o;var n=Object.create(null);if(q.r(n),Object.defineProperty(n,''default'',{enumerable:!0,value:o}),2&t&&''string''!=typeof o)for(var e in o)q.d(n,e,function(t){return o[t]}.bind(null,e));return n},q.n=function(o){var t=o&&o.__esModule?function(){return o.default}:function(){return o};return q.d(t,''a'',t),t},q.o=function(o,t){return Object.prototype.hasOwnProperty.call(o,t)},q.p=''/'',q(q.s=62)}({0:function(o,t,q){''use strict'';(function(o,n){vare;q.d(t,''a'',function(){return basicScroll}),function(t){''object''==typeof exports&&void 0!==o?o.exports=t():''function''==typeof define&&q(45)?define([],t):(''undefined''!=typeof window?window:void 0!==n?n:''undefined''!=typeof self?self:this).basicScroll=t()}(function(){return function o(t,q,n){function r(U,a){if(!q[U]){if(!t[U]){if(!a&&''function''==typeof e&&e)return e(U,!0);if(V)return V(U,!0);var i=new Error(''Cannot find module '''+U+''''');throwi.code=''MODULE_NOT_FOUND'',i}var p=q[U]={exports:{}};t[U][0].call(p.exports,function(o){return r(t[U][1][o]||o)},
    ";

    fn round_trip<C: Compressor>(label: &str) {
        let compressed = C::compress(SAMPLE).expect("compress failed");
        let decompressed = C::decompress(&compressed).expect("decompress failed");
        assert_eq!(decompressed, SAMPLE, "{label}: round-trip mismatch");

        println!(
            "{label}: {} -> {} bytes ({:.2}%)",
            SAMPLE.len(),
            compressed.len(),
            compressed.len() as f64 / SAMPLE.len() as f64 * 100.0
        );
    }

    #[test]
    fn test_lz4()  { round_trip::<Lz4>("lz4");   }
    #[test]
    fn test_gzip() { round_trip::<Gzip>("gzip"); }
    #[test]
    fn test_zstd() { round_trip::<Zstd>("zstd"); }

    // ====================== Bomb Protection Tests ======================

    #[test]
    fn test_gzip_bomb_rejected() {
        let mut compressed = Gzip::compress(SAMPLE).expect("compress failed");
        let len = compressed.len();
        // 篡改 gzip ISIZE 字段，声称解压后大小为 ~4GB
        compressed[len - 4..].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(Gzip::decompress(&compressed).is_none(), "gzip bomb should be rejected");
    }

    #[test]
    fn test_zstd_large() {
        let large_data = vec![0u8; 50 * 1024 * 1024]; // 50MB
        let compressed = Zstd::compress(&large_data).expect("compress failed");
        let decompressed = Zstd::decompress(&compressed);
        assert!(decompressed.is_none());
    }

    #[test]
    fn test_empty_input() {
        let empty = b"";
        assert_eq!(Lz4::compress(empty).as_deref().and_then(Lz4::decompress), Some(vec![]));
        assert_eq!(Gzip::compress(empty).as_deref().and_then(Gzip::decompress), Some(vec![]));
        assert_eq!(Zstd::compress(empty).as_deref().and_then(Zstd::decompress), Some(vec![]));
    }

    #[test]
    fn test_invalid_data_returns_none() {
        let garbage = b"this is definitely not valid compressed data!!!";

        assert!(Lz4::decompress(garbage).is_none());
        assert!(Gzip::decompress(garbage).is_none());
        assert!(Zstd::decompress(garbage).is_none());
    }
}