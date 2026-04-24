# code-auth


## 项目结构
```bash
❯ treee
./
├── lib/
│   ├── Cargo.lock
│   ├── Cargo.toml
│   └── src/
│       ├── _code.rs
│       ├── _lib_aes.rs
│       ├── _lib_base.rs
│       ├── _lib_compress.rs
│       ├── _lib_hash.rs
│       ├── lib.rs
│       ├── _lib_rsa.rs
│       └── main.rs
├── package.json
├── README.md
├── sdk/
│   ├── client/
│   │   └── wasm/
│   │       ├── Cargo.lock
│   │       ├── Cargo.toml
│   │       ├── LICENSE_APACHE
│   │       ├── LICENSE_MIT
│   │       ├── pkg/
│   │       │   ├── auth_bg.wasm
│   │       │   ├── auth_bg.wasm.d.ts
│   │       │   ├── auth.d.ts
│   │       │   ├── auth.js
│   │       │   ├── package.json
│   │       │   └── README.md
│   │       ├── README.md
│   │       ├── src/
│   │       │   ├── a_aes.rs
│   │       │   ├── a_rsa.rs
│   │       │   ├── doc.md
│   │       │   └── lib.rs
│   │       ├── tests/
│   │       │   └── web.rs
│   │       └── tsconfig.json
│   └── server/
│       └── wasm/
│           ├── Cargo.lock
│           ├── Cargo.toml
│           ├── LICENSE_APACHE
│           ├── LICENSE_MIT
│           ├── README.md
│           ├── src/
│           │   ├── lib.rs
│           │   └── utils.rs
│           └── tests/
│               └── web.rs
└── server_hono/
    ├── package.json
    ├── public/
    ├── src/
    │   ├── config.ts
    │   ├── html/
    │   │   ├── html.ts
    │   │   └── superAdminPage.html
    │   ├── index.ts
    │   ├── routes/
    │   │   ├── api.ts
    │   │   └── superAdmin.ts
    │   ├── test/
    │   │   └── a.ts
    │   └── tool/
    │       ├── aes.ts
    │       ├── base64.ts
    │       ├── code.ts
    │       ├── hash.ts
    │       ├── product.ts
    │       ├── rsa.ts
    │       └── tool.ts
    ├── tsconfig.json
    ├── worker-configuration.d.ts
    └── wrangler.jsonc

20 directories, 56 files

执行时间: 0.00 秒

```

> server_hono是旧版本项目，计划将更新使用统一的rust sdk（sdk/server/wasm/）
> sdk/client/wasm/是旧版本项目的客户端sdk,计划将更新使用统一的rust sdk