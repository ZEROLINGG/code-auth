# AGENTS.md - Code Auth Development Guide

This document provides guidelines for agentic coding agents working in this repository.

---

## 1. Build, Test & Lint Commands

### Rust (lib/)
```bash
# Build the library
cargo build

# Run all tests
cargo test

# Run library tests only
cargo test --lib

# Run a single test by name (partial match)
cargo test test_aes128gcm_round_trip

# Run tests matching a pattern
cargo test aes

# Check code (lint + compile)
cargo check

# Format code
cargo fmt

# Format with options
cargo fmt -- --check

# Run clippy lints
cargo clippy -- -D warnings

# Build WASM (from project root)
cd lib && cargo build --target wasm32-unknown-unknown
```

### TypeScript / Cloudflare Workers (server_hono/)
```bash
# Install dependencies
npm install

# Development server
npm run dev

# Deploy to Cloudflare
npm run deploy

# Type check
npx tsc --noEmit
```

### WASM SDK (sdk/)
```bash
# Build WASM package
cd sdk/client/wasm && wasm-pack build --target web

# Test WASM in browser
wasm-pack test --chrome
```

---

## 2. Code Style Guidelines

### 2.1 Rust Convention

**File & Module Naming**
- Core modules: `_lib_<feature>.rs` (e.g., `_lib_aes.rs`, `_lib_hash.rs`)
- Underscore prefix indicates internal module
- Re-export with clean names in `lib.rs`:

```rust
pub mod _lib_aes;
pub use crate::_lib_aes as aes;
```

**Naming Conventions**
- Types/Traits: `CamelCase` (e.g., `Aes256Gcm`, `Cipher` trait)
- Functions/Variables: `snake_case` (e.g., `encrypt`, `cached_key`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `MAX_COMPRESSION_RATIO`)
- Tests: `snake_case` with `test_` prefix (e.g., `test_aes128gcm_round_trip`)

**Error Handling**
- Return `Option<T>` for operations that can fail (e.g., `None` on invalid key)
- Use `?` operator for error propagation
- Avoid unwrap in public APIs

```rust
fn decrypt<T: AsRef<[u8]>>(key: &[u8], ciphertext: T) -> Option<Vec<u8>> {
    // Validate first
    if key.len() != $key_len || ciphertext.len() < 12 {
        return None;
    }
    // ... operation
    cipher.decrypt(nonce, data).ok()
}
```

**Generic Constraints**
- Use `T: AsRef<[u8]>` for flexible byte input
- Prefer bounded traits over bare generics

**Imports**
- Group by: std → external → local
- Use full paths for traits (e.g., `aes_gcm::aead::Aead`)

### 2.2 TypeScript Convention

**Naming**
- Classes: `PascalCase` (e.g., `AES`, `Base64`)
- Functions/Variables: `camelCase` (e.g., `encryptToBase64`)
- Constants: `SCREAMING_SNAKE_CASE` with `static readonly`

**TypeScript Config** (from `tsconfig.json`)
- `strict: true` - enforce full type checking
- `target`: `ESNext`
- `module`: `ESNext`
- `moduleResolution`: `Bundler`

**Error Handling**
- Use try/catch blocks
- Check error type before message extraction:

```typescript
} catch (error) {
    throw new Error(
        `Decryption failed: ${error instanceof Error ? error.message : String(error)}`
    );
}
```

**JSDoc Comments**
- Document public methods with `@param`, `@returns`, `@throws`

---

## 3. Project Structure

```
code-auth/
├── lib/                      # Rust core library (canonical)
│   └── src/
│       ├── lib.rs            # Exports
│       ├── _lib_aes.rs      # AES-GCM
│       ├── _lib_rsa.rs     # RSA
│       ├── _lib_hash.rs    # SHA-256, BLAKE3
│       ├── _lib_compress.rs # LZ4, zstd, gzip
│       └── _lib_base.rs    # Base64
│
├── server_hono/              # Cloudflare Workers (uses lib)
│   └── src/
│       ├── tool/            # TS crypto implementations
│       └── routes/          # API routes
│
└── sdk/
    ├── client/wasm/         # Browser WASM SDK (legacy)
    └── server/wasm/        # Server WASM SDK
```

---

## 4. Design Patterns

### 4.1 Trait-Based Architecture (Rust)

Define traits for algorithm families:

```rust
pub trait Cipher {
    fn encrypt<T: AsRef<[u8]>>(key: &[u8], plaintext: T) -> Option<Vec<u8>>;
    fn decrypt<T: AsRef<[u8]>>(key: &[u8], ciphertext: T) -> Option<Vec<u8>>;
}
```

Implement for concrete types:

```rust
pub struct Aes256Gcm;
impl Cipher for Aes256Gcm { /* ... */ }
```

### 4.2 Macro for Boilerplate

Use macros to reduce repetitive implementations:

```rust
macro_rules! impl_gcm_cipher {
    ($struct:ty, $cipher_type:ty, $key_len:expr) => {
        impl Cipher for $struct { /* ... */ }
    };
}
```

### 4.3 Static Configuration (TypeScript)

Group constants in static readonly object:

```typescript
static CRYPTO_CONFIG = {
    IV_LENGTH: 12,
    MIN_ENCRYPTED_LENGTH: 28,
    ALGORITHM: 'AES-GCM',
} as const;
```

---

## 5. Testing Guidelines

### Test Function Naming
- `<algorithm>_<scenario>_<expected>` (e.g., `test_aes256gcm_wrong_key`)

### Common Test Patterns

```rust
#[test]
fn test_round_trip() {
    let encrypted = C::encrypt(key, PLAINTEXT).expect("encrypt failed");
    let decrypted = C::decrypt(key, &encrypted).expect("decrypt failed");
    assert_eq!(decrypted, PLAINTEXT);
}
```

### Test Fixtures
- Place test constants in `mod tests` within the same file
- Use meaningful test data (avoid random bytes in examples)

---

## 6. Security Considerations

- Never commit secrets, keys, or credentials
- Use environment variables for sensitive configuration
- Clear sensitive data from memory when done (see `clearCache()`)
- Validate all inputs (key length, data size limits)
- Use constant-time comparison where appropriate for secrets