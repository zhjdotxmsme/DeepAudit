# WSTG-INFO: 信息收集

## 检测清单

- [ ] 识别 Web 服务器指纹（Server 头、X-Powered-By）
- [ ] 识别应用框架和版本
- [ ] 发现隐藏/非公开端点（robots.txt, sitemap.xml, .well-known/）
- [ ] 目录枚举（.git/, .env, backups, admin）
- [ ] 注释中泄露的信息（HTML/JS 注释含内网IP、凭证）
- [ ] API 文档端点（/swagger, /docs, /openapi.json, /graphql?introspection）
- [ ] WAF/IPS 指纹识别
- [ ] 第三方组件版本暴露
- [ ] 应用错误信息泄露（500 错误页含堆栈跟踪）

## 危险模式

```javascript
// HTML 注释泄露内网信息
<!-- TODO: 修复这个bug - 联系 admin@internal.company.com -->
<!-- DB 连接: jdbc:mysql://10.0.0.5:3306/prod -->

// JS 文件中的 API 端点
const API = {
    base: 'https://internal-api.company.com/v2',
    admin: '/admin/console',
    upload: '/upload?token=sk_test_xxxx'
}
```

```python
# 错误处理泄露堆栈
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        "error": str(error),       # 泄露内部路径
        "traceback": traceback.format_exc()  # 泄露代码结构
    }), 500
```

## OWASP 映射: A05:2021 Security Misconfiguration
