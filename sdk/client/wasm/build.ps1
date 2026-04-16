#!pwsh
# build.ps1 - 构建 Rust WASM 项目并生成绑定文件

# 1️⃣ 设置 Rust 编译器标志，关闭所有未使用警告
$env:RUSTFLAGS = "-A unused"

# 构建 Rust 项目为 WebAssembly 目标（release 模式）
Write-Host "Building Rust project for wasm32-unknown-unknown..."
cargo build --target wasm32-unknown-unknown --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed!"
    exit $LASTEXITCODE
}

# 使用 wasm-bindgen 生成 JS/TS 绑定文件，输出到 wasm/ 目录
Write-Host "Generating wasm-bindgen bindings..."
wasm-bindgen target/wasm32-unknown-unknown/release/auth.wasm --out-dir wasm --target web
if ($LASTEXITCODE -ne 0) {
    Write-Error "wasm-bindgen failed!"
    exit $LASTEXITCODE
}

Write-Host "Build completed successfully! Output in ./wasm/"
