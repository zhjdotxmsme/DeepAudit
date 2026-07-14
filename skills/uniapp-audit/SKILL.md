---
name: uniapp-audit
version: 1.0.0
category: framework
description: uni-app 跨端应用安全审计（H5 / 小程序 / App / 5+ Runtime）
author: DeepAudit
targets:
  languages: [javascript, typescript, vue]
  frameworks: [uni-app, uniapp, uniapp-x, dcloud, 5plus, hbuilder]
cwe_tags:
  - CWE-79    # XSS
  - CWE-918   # SSRF
  - CWE-94    # Code Injection
  - CWE-540   # Sensitive Info in Source
  - CWE-284   # Access Control
  - CWE-829   # Inclusion of Functionality from Untrusted Sphere
severity_focus: [high, medium]
tags: [uniapp, cross-platform, mobile, h5, mini-program, dcloud]
references:
  - references/uni-request-ssrf.md
  - references/conditional-compile-leak.md
  - references/evaluate-js-injection.md
  - references/plus-runtime-api.md
  - references/h5plus-permission-bypass.md
scripts: []
---

# uni-app 跨端应用安全审计

uni-app 一份代码打 H5 / 微信小程序 / 支付宝小程序 / iOS App / Android App / 快应用，
每个平台安全边界不同。审计核心：**条件编译泄漏 + 5+ Runtime API 滥用 + WebView 桥接**。

## 优先审计的攻击面

1. **`uni.request` URL 拼接 SSRF-in-mobile (CWE-918)** — 前端拿到用户输入直接
   `uni.request({ url: '/api/' + userInput })`；小程序场景下配合业务域名白名单绕过
   可打后端。
2. **条件编译 `#ifdef H5` 泄漏 (CWE-540)** — 开发者在 `#ifdef MP-WEIXIN` 里写死 AK/SK，
   H5 编译时被 tree-shaking 剥离但 sourcemap 保留；反过来 `#ifdef APP-PLUS` 分支
   在 H5 编译产物中仍含代码。检测：搜 `#ifdef.*AK|SECRET|TOKEN`。
3. **`uni.evaluateJavaScript` 代码注入 (CWE-94)** — WebView 组件调用
   `wv.evaluateJavaScript("callback('" + data + "')")`，data 来自后端或用户输入即
   JS 注入。
4. **5+ Runtime `plus.runtime.launchApplication` 权限提升 (CWE-284)** — 通过
   `plus.runtime.openURL(url)` 可打开任意 scheme，包括 `intent://` 攻击其他 App；
   `plus.runtime.install(apk)` 静默安装。
5. **`plus.io` 文件系统越权 (CWE-22)** — `plus.io.resolveLocalFileSystemURL("_www/...")`
   若参数可控可读取沙箱外文件（Android 早期版本）。
6. **`plus.oauth.getServices()` 三方登录劫持** — 未校验 `state` / `code` 来源。
7. **`onLaunch` 中的 `getEnterOptionsSync()`** — 小程序 scheme 参数直接进入路由 —
   `pages/detail?id=${scheme.query.id}` 结合 v-html 即 XSS。
8. **`uni.getStorageSync` 存 token** — 小程序沙箱可通过工具导出；H5 端等价于 localStorage。
9. **`webview` src 拼接 (CWE-79 + CWE-601)** — `<web-view :src="userUrl" />` 未白名单，
   小程序审核可过但客户端可打开钓鱼页。
10. **原生插件通信 (nativePlugin) 未校验来源** — 自定义 native 插件的 `postMessage`
    handler 若未校验 origin，Web 页面可任意调用原生能力。

## 审计动作 checklist

- [ ] 全局 grep `#ifdef` / `#ifndef` 条件编译块，逐块检查是否含机密
- [ ] `uni.request` / `uni.uploadFile` / `uni.downloadFile` 所有 URL 传入点
- [ ] `<web-view>` / `wv.evaluateJavaScript` 所有使用
- [ ] `plus.runtime.*` / `plus.io.*` / `plus.nativeObj.*` 家族 API 使用
- [ ] `manifest.json` 权限声明（`permissions`、`app-plus.distribute.android.permissions`）
- [ ] 小程序 `getEnterOptionsSync()` / `onLoad(options)` 参数使用链
- [ ] 三方登录（`uni.login` / `plus.oauth`）state/code 校验
- [ ] 是否使用 uni-secure-network / requiredPrivateInfos 声明真实性

## 参考文档

- `references/uni-request-ssrf.md`
- `references/conditional-compile-leak.md`
- `references/evaluate-js-injection.md`
- `references/plus-runtime-api.md`
- `references/h5plus-permission-bypass.md`
