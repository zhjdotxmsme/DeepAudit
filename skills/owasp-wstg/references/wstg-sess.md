# WSTG-SESS: 会话管理

## 检测清单

- [ ] Session ID 可预测（非加密随机数）
- [ ] Cookie 缺少安全标志（Secure, HttpOnly, SameSite）
- [ ] Session 固定攻击（登录后不更换 session ID）
- [ ] CSRF Token 缺失或可预测
- [ ] Session 超时设置过长或不设置
- [ ] 登出不销毁 session
- [ ] Session 在多设备间不隔离
- [ ] Token 存储在 LocalStorage（易受 XSS 窃取）
- [ ] 并发登录无限制

## CSRF 检测

```python
# 危险 - 状态变更无 CSRF 保护
@app.route('/api/transfer', methods=['POST'])
def transfer():
    execute_transfer(request.form['to'], request.form['amount'])
    return {"status": "ok"}

# 安全 - 验证 CSRF Token
@app.route('/api/transfer', methods=['POST'])
@csrf_protect
def transfer():
    execute_transfer(request.form['to'], request.form['amount'])
    return {"status": "ok"}
```

```javascript
// 危险 - Token 存入 localStorage
localStorage.setItem('access_token', jwtToken);
// 被 XSS 窃取后，攻击者可完全接管会话

// 安全 - HttpOnly Cookie（前端不可读）
document.cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict";
```

## OWASP 映射: A07:2021 Identification and Authentication Failures
