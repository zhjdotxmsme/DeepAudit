# WSTG-CLIENT: 客户端安全

## 检测清单

- [ ] DOM XSS（innerHTML、document.write、危险 setter）
- [ ] Content Security Policy 缺失或过于宽松（unsafe-inline、unsafe-eval）
- [ ] postMessage 目标源未验证（任意页面通信）
- [ ] LocalStorage/SessionStorage 存储敏感数据（Token、PII）
- [ ] 第三方脚本加载（CDN JavaScript、分析脚本、广告）
- [ ] WebSocket 未验证来源
- [ ] iframe 嵌入保护（X-Frame-Options / frame-ancestors）
- [ ] 前端路由鉴权仅作 UI 隐藏（后端未同步验证）
- [ ] Service Worker 中间人风险
- [ ] 浏览扩展/插件接口暴露

## DOM XSS

```javascript
// 危险
document.getElementById('output').innerHTML = userInput;
document.write(location.hash.slice(1));
element.outerHTML = userInput;

// 安全
document.getElementById('output').textContent = userInput;
element.innerText = userInput;
```

## postMessage

```javascript
// 危险 - 未验证 origin
window.addEventListener('message', function(event) {
    eval(event.data);  // 任意域的恶意页面可注入代码
});

// 安全
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted-domain.com') return;
    try {
        const data = JSON.parse(event.data);
        // 安全处理
    } catch (e) {
        console.error('Invalid message');
    }
});
```

## CSP 配置

```http
// 推荐 CSP 策略
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'
```

## OWASP 映射: A03:2021 Injection
