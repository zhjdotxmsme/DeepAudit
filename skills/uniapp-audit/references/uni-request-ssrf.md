# uniapp uni.request 与 SSRF / 任意 URL 请求

## 场景

uniapp 应用（H5、小程序、App）常用 `uni.request` 发起网络请求。若 URL 由用户输入
拼接或来自服务端可控参数 → SSRF 风险；此外域名白名单缺失时可被用做流量转发。

## 危险模式

### 客户端 SSRF

```js
// ❌ URL 完全来自服务端接口返回
uni.request({
  url: response.imageProxy,   // 服务端字段可控 → 客户端替攻击者请求任意资源
  success: (res) => { ... }
});
```

某些情况下这会暴露：
- 用户 IP（客户端 IP 发起请求）
- 内网可达资源（App 部署在办公网/CI 环境）
- 会话 Cookie / Authorization header（若默认带上）

### query 参数拼接

```js
// ❌ 攻击者控制 url 通过反射注入
const target = getUrlParam("callback");
uni.request({ url: target });
```

拼接来源：
- URL query（H5）
- 小程序 launch options
- `getApp().globalData.xxx`（登录 redirect chain 被污染）
- 5+ webview `postMessage` 数据

### 白名单缺失

manifest.json 内应配置：

```json
{
  "h5": {
    "devServer": {
      "proxy": { }
    }
  },
  "app-plus": {
    "safeHostList": ["api.example.com", "cdn.example.com"]
  },
  "mp-weixin": {
    "requestDomain": ["https://api.example.com"]
  }
}
```

若小程序 `requestDomain` 走 "业务域名管理" 白名单缺失或使用"跳过域名校验" 开发模式
部署 → 任意域名。

## 安全模式

### 强制白名单校验

```js
// utils/request.js
const ALLOWED = ['api.example.com', 'cdn.example.com'];

function safeRequest(options) {
  const url = new URL(options.url);
  if (!ALLOWED.includes(url.hostname)) {
    throw new Error('Blocked host: ' + url.hostname);
  }
  return uni.request(options);
}
```

### 服务端代理

不直接从客户端请求第三方，服务端做代理并做校验（内网 IP 拒绝、SSRF 白名单）。

### 完整 URL 而非拼接

```js
// ❌
url: 'https://api.example.com/user/' + userInput

// ✅
url: 'https://api.example.com/user/' + encodeURIComponent(userId)
```

且服务端 userId 走 authenticated session，不接受客户端传参。

## Referer / Origin 校验

服务端识别客户端来源：
- 小程序 `Referer: https://servicewechat.com/wxAppId/...`
- App WebView 可自定义 UA / 无 Referer

若服务端依赖 Referer 做鉴权 = 弱鉴权。

## 审计动作

```bash
grep -rn 'uni.request\|uni.uploadFile\|uni.downloadFile\|uni.connectSocket' src/
```

对每个匹配：
- URL 是常量吗？
- 是来自服务端接口的字段吗？
- 是否走 utils/safeRequest 中间层？

manifest.json：
- [ ] `mp-weixin.requestDomain` / `socketDomain` 白名单存在
- [ ] `app-plus` 是否有 safeHostList

## 相关规则

- CWE: CWE-918 (SSRF)
- CWE: CWE-601 (Open Redirect)
- 内建 pattern: `uniapp_uni_request`
- CVSS: 7.5
