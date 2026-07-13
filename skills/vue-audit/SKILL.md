---
name: vue-audit
version: 1.0.0
category: framework
description: Vue / Vite / 前端 SPA 安全审计知识包
author: DeepAudit
targets:
  languages: [javascript, typescript]
  frameworks: [vue, vue2, vue3, vite, nuxt, element-plus, element-ui]
cwe_tags:
  - CWE-79    # XSS
  - CWE-601   # Open redirect
  - CWE-918   # SSRF (frontend as attack vector)
  - CWE-522   # Credentials in localStorage
  - CWE-540   # Sensitive info in source (VITE_*)
  - CWE-1021  # Clickjacking
severity_focus: [high, medium]
tags: [vue, frontend, spa, vite, xss]
references:
  - references/v-html-xss.md
  - references/route-guard-bypass.md
  - references/vite-env-leak.md
  - references/token-storage.md
scripts: []
---

# Vue / 前端 SPA 安全审计

面向 Vue2 / Vue3 / Vite / Nuxt 项目的专项审计知识。前端漏洞多为
"配合服务端漏洞放大杀伤" 的角色（token 泄漏、XSS、开放重定向、
后台 API 暴露），审计时注意配合 `springboot-audit` 之类后端 Skill 使用。

## 优先审计的攻击面

1. **v-html XSS (CWE-79)** — `<div v-html="content" />` 且 content 来自
   后端返回或 URL 参数，未走 DOMPurify。Vue3 `<component :is="dyn" />`
   若 dyn 为字符串同样危险。
2. **`eval` / `new Function` 家族** — Vue Options 里 `computed`/`watch`
   动态求值用户表达式；`vue-i18n` 的 legacy mode `$t` 允许 HTML 时也会 XSS。
3. **路由守卫绕过** — `router.beforeEach` 里只判 `!token` 就 `next()`，
   而后台在 `mounted` 中挂了敏感请求。前端"鉴权"永远不是鉴权。
4. **Token / 敏感信息存 localStorage** — XSS 可读，`httpOnly cookie`
   是唯一正确答案（PWA / 移动端另议）。
5. **`.env` VITE_ 前缀泄漏** — `VITE_*` 变量会被打包进前端 bundle，
   任何写入 `VITE_SECRET_KEY` / `VITE_INTERNAL_API` 都等于把它公开。
6. **Axios `baseURL` / `open redirect`** — `window.location.href = query.next`
   未白名单校验；`axios.create({ baseURL: dynamic })` 引入 SSRF-in-browser。
7. **CSP / SRI / Clickjacking** — 缺失 `X-Frame-Options` 或 CSP `frame-ancestors`；
   `<script src="cdn/...">` 未加 SRI；`unsafe-eval` 在 CSP 中。
8. **`vue-router` history mode 路径拼接 SSRF-回环** — SSR / Nuxt 下将
   query 直接透传给后端 fetch。

## 审计动作 checklist

- [ ] 所有 `v-html` / `innerHTML` / `outerHTML` / `document.write` 使用点，
      来源是否可控且未消毒？
- [ ] `beforeEach` / `beforeEnter` 是否做过权限判定？服务端是否有对应校验？
- [ ] `localStorage.setItem` / `sessionStorage.setItem` 是否存放了 token/密钥？
- [ ] `.env*` 中带 `VITE_` 前缀的变量是否有真正的秘密？
- [ ] 路由跳转 / `window.location` 赋值是否白名单？
- [ ] `index.html` / meta 头是否配置了 CSP + `X-Frame-Options: DENY`？

## 参考文档

- `references/v-html-xss.md`
- `references/route-guard-bypass.md`
- `references/vite-env-leak.md`
- `references/token-storage.md`
