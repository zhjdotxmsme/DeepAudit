# 前端 Token / 敏感信息存储

## 存储选项对比

| 位置 | XSS 能读 | CSRF 需防 | 备注 |
|------|----------|-----------|------|
| `localStorage` | ✅ 能读 | ❌ 不受影响 | 最常见但最不安全 |
| `sessionStorage` | ✅ 能读 | ❌ 不受影响 | 关闭标签就没，UX 差 |
| 普通 Cookie | ✅ 能读（若无 `HttpOnly`）| ✅ 需 CSRF | |
| `HttpOnly` Cookie | ❌ 读不到 | ✅ 需 CSRF | **推荐** |
| 内存变量 | ✅ 能读 | ❌ 不受影响 | 刷新丢失，UX 差 |

## 推荐方案

**后端下发 `HttpOnly; Secure; SameSite=Strict; Path=/` 的 Cookie 承载 Session/JWT。**

```
Set-Cookie: session=eyJ...; HttpOnly; Secure; SameSite=Strict; Path=/
```

前端不再持有 token，只靠浏览器带 Cookie。CSRF 用 `SameSite=Strict`
或双 Cookie 模式解决。

## 常见错误 pattern

```js
// ❌ 危险
localStorage.setItem('access_token', resp.data.token)
axios.defaults.headers.common['Authorization'] = `Bearer ${resp.data.token}`

// ❌ 更危险：把 refresh_token 也放前端
localStorage.setItem('refresh_token', resp.data.refresh)
```

一旦 v-html / 第三方脚本 / npm 供应链 XSS，一次性丢失所有会话。

## 若必须用 localStorage

- 短期 access token（≤ 15 min），refresh 走 HttpOnly Cookie
- 严格 CSP：`default-src 'self'`，禁 `unsafe-eval` / `unsafe-inline`
- 所有 v-html 走 DOMPurify
- 第三方脚本必加 SRI

## 检测

- Grep `localStorage.setItem\((['"])(token|access|refresh|jwt|auth|session)`
- Grep `Cookie` 相关配置里是否有 `HttpOnly`
- 检查登录接口响应 `Set-Cookie` 头
