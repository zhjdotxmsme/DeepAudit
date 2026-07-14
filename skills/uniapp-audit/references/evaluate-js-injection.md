# uniapp WebView 与 JS 执行注入

## uni.evaluateJavaScript

App 端可以向 web-view 组件注入执行 JS：

```vue
<template>
  <web-view :src="pageUrl" @message="onMessage" ref="wv"/>
</template>

<script>
export default {
  methods: {
    inject(code) {
      // App-plus 侧
      const wv = this.$refs.wv;
      wv.evalJS(code);   // 或
      plus.webview.getWebviewById('page').evalJS(code);
    }
  }
}
</script>
```

若 `code` 来自：
- 服务端接口字段
- 深链参数
- 上一页面 postMessage

→ 攻击者构造 JS，在 web-view 上下文执行，读取 cookie、localStorage、window 对象。

危险等级取决于 web-view 上下文：
- 加载信任域名（自家站点）→ 窃取用户登录 session
- 加载支付跳转页 → 篡改金额/收款人
- 加载 chromeless / native bridge 页 → 调用 plus API 提权到设备

## 反向：Web → App bridge

web-view 内可通过 `uni.postMessage` 回传消息：

```html
<script>
  uni.postMessage({
    data: userSuppliedData   // ⚠️ 网页上可控内容
  });
</script>
```

App 端接收：

```js
onMessage(e) {
  const cmd = e.detail.data[0].cmd;    // 攻击者可控
  this.execCmd(cmd);                    // 若 cmd 触发 evalJS 二次注入
}
```

若 execCmd 未做类型 / 白名单过滤，可组合成 **网页 → App JS 上下文 → plus API**
的提权链。

## plus.runtime.execute / openURL

```js
// ❌ 打开任意 App / 深链
plus.runtime.openURL(userInput);
```

`userInput` 可为：
- `intent://...` / `market://...`（Android）
- `itms-apps://...`（iOS）
- 自定义 URL Scheme → 触发第三方 App 敏感操作

## 安全模式

### 1. evalJS 白名单

```js
const ALLOWED_JS = ['setUser', 'refreshToken'];

function safeEvalJS(wv, name, ...args) {
  if (!ALLOWED_JS.includes(name)) throw new Error('Blocked');
  wv.evalJS(`window.${name}(${JSON.stringify(args)})`);
}
```

绝不直接把用户输入拼进 `evalJS`。

### 2. postMessage 来源校验

```js
onMessage(e) {
  const wv = this.$refs.wv;
  const srcUrl = plus.webview.getWebviewById(wv.id).getURL();
  if (!srcUrl.startsWith('https://trusted.example.com/')) return;
  // ...
}
```

### 3. web-view src 白名单

```vue
<web-view :src="isAllowed(url) ? url : 'about:blank'"/>
```

```js
function isAllowed(u) {
  try {
    const p = new URL(u);
    return ['trusted.example.com'].includes(p.hostname) && p.protocol === 'https:';
  } catch { return false; }
}
```

### 4. URL Scheme 白名单

```js
function safeOpen(url) {
  const p = new URL(url);
  if (!['https:', 'http:', 'weixin:'].includes(p.protocol)) throw new Error();
  plus.runtime.openURL(url);
}
```

## 审计动作

```bash
grep -rEn 'evalJS|evaluateJavaScript|plus.runtime.execute|plus.runtime.openURL|uni.postMessage' src/
```

- [ ] 参数是常量 / 白名单枚举？
- [ ] web-view src 是否可控？
- [ ] postMessage 是否校验来源 URL？

## 相关规则

- CWE: CWE-79 (XSS in WebView)
- CWE: CWE-94 (Code Injection)
- 内建 pattern: `uniapp_eval_js`
- CVSS: 8.8
