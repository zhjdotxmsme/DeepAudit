# uniapp 条件编译与密钥泄露

## 条件编译语法

```js
// #ifdef MP-WEIXIN
const secret = "wx-mp-only-secret";
// #endif

// #ifdef APP-PLUS
const nativeToken = "app-plus-token";
// #endif

// #ifndef H5
const desktopKey = "not-h5";
// #endif
```

编译期根据目标平台决定保留哪些代码块。**编译输出**的代码里，非当前平台分支会被剥离。

## 泄露风险

### 1. H5 输出泄露非 H5 密钥

若 `// #ifdef MP-WEIXIN` 未正确闭合，或写成 `// #ifdef APP-PLUS || H5` → H5
构建也会把 App 端密钥打包进 JS bundle → 前端可 F12 看到。

例：

```js
// ❌ 逻辑写错，导致 H5 也保留
// #ifndef MP-WEIXIN
const APP_SECRET = "sk-xxxx";   // 想只给 App 端，实际 H5 也保留
// #endif
```

### 2. 编译常量硬编码

```js
// vite / webpack define 注入
define: {
  '__API_KEY__': JSON.stringify(process.env.API_KEY),
}
```

编译后 bundle 中所有 `__API_KEY__` 替换为字面量 → 客户端泄露。

### 3. manifest 字段泄露

`manifest.json` 中的 `appid`、`微信小程序 appId + secret`、`支付宝 appid` 常常
连同 secret 一起写入。secret **不应出现在客户端**。

## 检测

打包后：

```bash
# H5 dist 目录
grep -rn 'sk-\|_secret\|SECRET\|API_KEY' dist/build/h5/

# 小程序
grep -rn 'sk-\|_secret\|SECRET\|API_KEY' unpackage/dist/build/mp-weixin/
```

若发现明文密钥字符串 → 立即失效并 rotate。

## 正确做法

### 1. 客户端不放服务端密钥

服务端 API 走 session token；密钥留在后端。

### 2. 短生命周期 client token

若 client 必须持有 credential：
- 通过登录后颁发短期 JWT（15 min - 2 h）
- 走 HttpOnly Cookie（H5）或本地加密存储（App）
- **绝不** 硬编码到源码

### 3. 环境隔离

`env.development.js` / `env.production.js`：

```js
// ❌ 生产环境的密钥
export default {
  API_KEY: 'sk-prod-xxx'
};
```

改为运行时注入：

```js
// 从后端登录接口获取
uni.request({
  url: '/api/session',
  success: ({data}) => uni.setStorageSync('token', data.token)
});
```

### 4. 微信 mp 域名白名单不放 secret

`unipush.plist`、`AndroidManifest.xml`、`app.json` 需要 AppSecret 时，走
**服务端 → 微信 API**，客户端只传 code。

## 审计动作

```bash
# 源码 secret 硬编码
grep -rEn 'appSecret|api_?key|secret_?key|access_?token' src/ manifest.json
```

- [ ] 打包产物 dist/ 全文搜索 `sk-` / `AKID` / `SECRET_KEY`
- [ ] `// #ifdef` 与 `// #endif` 严格配对（Vite 插件报错检查）
- [ ] `manifest.json` 无生产 secret
- [ ] CI/CD 是否将 secret 从 build args 泄露到 bundle（webpack DefinePlugin 常见坑）

## 相关规则

- CWE: CWE-798 (Hardcoded Credentials)
- CWE: CWE-200 (Exposure of Sensitive Information)
- 内建 pattern: `uniapp_condition_compile_leak`
- CVSS: 7.5
