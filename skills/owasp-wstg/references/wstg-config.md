# WSTG-CONFIG: 配置管理

## 检测清单

- [ ] 默认凭证未修改（admin/admin, root/root）
- [ ] 调试/开发端点暴露（/actuator, /debug, /dev, /console）
- [ ] CORS 配置过于宽松（Access-Control-Allow-Origin: *）
- [ ] 安全头缺失（CSP, HSTS, X-Frame-Options, X-Content-Type-Options）
- [ ] 目录列表未禁用
- [ ] HTTP 方法覆盖（PUT/DELETE/TRACE 未限制）
- [ ] 敏感文件可访问（.git/config, .env, .aws/credentials）
- [ ] 容器配置安全（非 root 运行、只读文件系统、能力集限制）
- [ ] 云服务元数据端点暴露（169.254.169.254）
- [ ] 管理后台无需二次认证可访问

## 危险模式

```python
# CORS 配置过于宽松
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    # 危险：Allow-Credentials + Allow-Origin: * 违反规范
    return response
```

```java
// Spring Actuator 完全暴露
management.endpoints.web.exposure.include=*
management.endpoint.shutdown.enabled=true
// 生产环境需要认证
```

```python
# 调试模式开启
app.run(debug=True)  # 生产环境不应 debug=True
```

## OWASP 映射: A05:2021 Security Misconfiguration | A06:2021 Vulnerable Components
