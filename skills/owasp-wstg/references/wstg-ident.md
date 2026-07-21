# WSTG-IDENT: 身份认证

## 检测清单

- [ ] 登录接口无速率限制/无验证码
- [ ] 密码策略不足（长度、复杂度、历史）
- [ ] 密码找回功能存在枚举/绕过
- [ ] 记住我功能 token 不安全
- [ ] 多因素认证可绕过
- [ ] OAuth/SSO 实现缺陷（重定向 URI 未验证、state 参数缺失）
- [ ] JWT 未验证签名/未验证过期/使用弱算法(none/HS256 with public key)
- [ ] 注册接口可枚举用户
- [ ] Session 固定攻击
- [ ] 认证失败响应不一致（用户存在/不存在区分）
- [ ] 弱 Token 生成算法（可预测、基于时间戳、基于用户名 MD5）

## JWT 常见漏洞

```python
import jwt

# 危险 - 未验证签名
payload = jwt.decode(token, options={"verify_signature": False})

# 危险 - 算法混淆攻击
# 攻击者修改 header: {"alg": "none"}
# 服务端应拒绝 none 算法

# 危险 - 使用公钥作为 HS256 密钥
payload = jwt.decode(token, public_key, algorithms=["HS256"])
# 攻击者可通过注册页面获得公钥，伪造任意 token
```

```java
// 安全 JWT 配置
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    http.oauth2ResourceServer()
        .jwt()
        .decoder(jwtDecoder());
}
```

## OWASP 映射: A07:2021 Identification and Authentication Failures
