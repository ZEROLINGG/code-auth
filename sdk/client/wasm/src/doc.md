# 激活码系统接口文档

## 概述

本系统是一个基于 WebAssembly 的客户端激活码验证系统，采用 RSA + AES 混合加密方案，提供激活码验证、许可证管理等功能。

---

## API 端点

**基础 URL**: `https://auth.808050.xyz/api`

---

## 客户端类：`Auth`

### 构造函数

```javascript
new Auth(product_id: string, binding: string, license?: string)
```

**参数**:
- `product_id`: 产品 ID（必需）
- `binding`: 绑定信息（如设备标识，必需）
- `license`: 已有的许可证（可选）

**示例**:
```javascript
const auth = new Auth("my-product-123", "device-uuid-456");
```

---

### 方法

#### 1. `init()`

初始化客户端，完成密钥交换。

```javascript
await auth.init(): Promise<void>
```

**流程**:
1. 生成客户端 RSA 2048位密钥对
2. 向服务器发送公钥
3. 接收服务器公钥和客户端 UUID
4. 初始化 AES 加密器

**请求**: `POST /pub/key/exc`

```json
{
  "client_pub_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**响应成功**:
```json
{
  "status": "ok",
  "client_uuid": "uuid-string",
  "server_pub_key_pem": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**响应失败**:
```json
{
  "status": "error",
  "message": "错误描述",
  "code": 400
}
```

**异常**:
- `"Failed to generate RSA key pair"` - 密钥生成失败
- `"Invalid server public key"` - 服务器公钥格式错误
- `"API error: {message} (code: {code})"` - 服务器返回错误

---

#### 2. `auth(code)`

使用激活码进行激活，返回许可证。

```javascript
await auth.auth(code: string): Promise<AuthResult>
```

**参数**:
- `code`: 激活码字符串

**返回类型**:
```typescript
interface AuthResult {
  success: boolean;
  license?: string;  // 成功时返回加密的许可证
}
```

**请求**: `POST /auth/reg/code`

```json
{
  "client_uuid": "uuid-string",
  "data_c": "RSA加密的(code:timestamp)",
  "data_i": "RSA加密的product_id",
  "data_b": "RSA加密的binding"
}
```

**响应成功**:
```json
{
  "status": "ok",
  "data": ["加密数据块1", "加密数据块2", ...]
}
```

**解密后的数据格式**:
```json
[
  true,                    // success
  "activation-uuid",       // 激活UUID
  31658502,               // code过期时间戳(相对)
  315482535,              // 激活时长(秒)
  "binding-hash",         // 绑定信息哈希
  4                       // 剩余激活次数
]
```

**示例**:
```javascript
const result = await auth.auth("ABC123XYZ");
if (result.success) {
  console.log("激活成功，许可证:", result.license);
  // 保存 license 供后续使用
}
```

**异常**:
- `"Client UUID not initialized"` - 未初始化
- `"Encrypt error"` - 加密失败
- `"API error: {message}"` - 服务器拒绝激活

---

#### 3. `check()`

验证现有许可证是否有效，并更新许可证。

```javascript
await auth.check(): Promise<AuthResult>
```

**前置条件**:
- 必须已设置 `license`
- 必须已调用 `init()`

**返回类型**: 同 `auth()`

**请求**: `POST /auth/again/reg/code`

```json
{
  "client_uuid": "uuid-string",
  "data_u": "RSA加密的activation_uuid",
  "data_b": "RSA加密的binding_hash"
}
```

**流程**:
1. AES 解密本地许可证
2. 提取 `activation_uuid` 和 `binding_hash`
3. RSA 加密后发送服务器验证
4. 接收新的许可证数据
5. AES 加密后返回

**示例**:
```javascript
const auth = new Auth("product-id", "binding", savedLicense);
await auth.init();
const result = await auth.check();
if (result.success) {
  // 更新本地存储的 license
  localStorage.setItem('license', result.license);
}
```

**异常**:
- `"License not found"` - 未提供许可证
- `"AES not initialized"` - 加密器未初始化
- `"License decrypt failed"` - 许可证解密失败
- `"Invalid license JSON"` - 许可证格式错误

---

#### 4. `info(code)`

解析激活码的元信息（无需联网）。

```javascript
auth.info(code: string): CodeInfo
```

**返回类型**:
```typescript
interface CodeInfo {
  success: boolean;
  code_expire_at: number;      // 激活码过期时间戳(毫秒)
  activation_duration: number; // 激活时长(秒)
  max_amount: number;          // 最大激活次数
}
```

**激活码格式**:
```
Base64([cipher_length(2字节)] + [加密数据] + [:code_expire:duration:max_amount])
```

**示例**:
```javascript
const info = auth.info("ABC123XYZ");
if (info.success) {
  const expireDate = new Date(info.code_expire_at);
  console.log("过期时间:", expireDate);
  console.log("激活时长:", info.activation_duration, "秒");
  console.log("剩余次数:", info.max_amount);
}
```

---

#### 5. `is_initialized` (getter)

检查是否已完成初始化。

```javascript
auth.is_initialized: boolean
```

**示例**:
```javascript
if (!auth.is_initialized) {
  await auth.init();
}
```

---

## 完整使用流程

### 首次激活

```javascript
// 1. 创建实例
const auth = new Auth("product-xyz", getDeviceId());

// 2. 初始化
await auth.init();

// 3. (可选) 解析激活码信息
const info = auth.info(userInputCode);
if (!info.success) {
  alert("激活码格式错误");
  return;
}

if (Date.now() > info.code_expire_at) {
  alert("激活码已过期");
  return;
}

// 4. 激活
const result = await auth.auth(userInputCode);
if (result.success) {
  // 保存许可证
  localStorage.setItem('license', result.license);
  alert("激活成功！");
} else {
  alert("激活失败");
}
```

### 验证已有许可证

```javascript
// 1. 从存储中加载许可证
const savedLicense = localStorage.getItem('license');
if (!savedLicense) {
  // 引导用户激活
  return;
}

// 2. 创建实例
const auth = new Auth("product-xyz", getDeviceId(), savedLicense);

// 3. 初始化
await auth.init();

// 4. 验证
try {
  const result = await auth.check();
  if (result.success) {
    // 更新许可证
    localStorage.setItem('license', result.license);
    // 允许使用软件
  } else {
    // 许可证无效，清除并引导重新激活
    localStorage.removeItem('license');
  }
} catch (e) {
  console.error("验证失败:", e);
}
```

---

## 错误处理

所有异步方法都返回 `Promise`，错误通过 `JsValue` 抛出：

```javascript
try {
  await auth.init();
} catch (error) {
  console.error("初始化失败:", error);
  // error 为字符串描述
}
```



---

## 安全注意事项

1. **绑定信息**: `binding` 应使用稳定的设备标识（如 MAC 地址哈希）
2. **许可证存储**: 加密存储 `license`，避免明文保存
3. **定期验证**: 建议每次启动应用时调用 `check()`

---


