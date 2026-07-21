# WSTG-API: API 安全

## 检测清单

- [ ] REST API 鉴权缺失或不一致
- [ ] GraphQL 自省查询未禁用
- [ ] GraphQL 批量查询（batch query/aliasing 绕过速率限制）
- [ ] GraphQL 深度查询（循环嵌套导致 DoS）
- [ ] gRPC 未启用 TLS/mTLS
- [ ] API Key 硬编码或泄露
- [ ] API 版本控制缺失
- [ ] 分页无限制（数据导出/遍历漏洞）
- [ ] 批量操作（Batch API）权限验证不足
- [ ] API 响应含敏感字段（密码哈希、Token、内网地址）
- [ ] Rate Limiting 缺失
- [ ] WebSocket 鉴权仅在建立连接时验证（未验证后续消息）

## GraphQL 安全

```graphql
# 危险 - 自省查询未禁用
{
    __schema {
        types {
            name
            fields { name type { name } }
        }
    }
}

# 危险 - 深度嵌套查询 DoS
query {
    user(id: 1) {
        posts { comments { user { posts { comments { ... } } } } }
    }
}

# 危险 - 别名批量查询绕过限流
query {
    a1: user(id: 1) { email }
    a2: user(id: 2) { email }
    a3: user(id: 3) { email }
    # ... 可一次查询大量数据
}
```

## REST API 安全

```python
# 危险 - API 鉴权缺失
@app.route('/api/admin/users')
def list_users():
    return User.query.all()  # 未验证是否管理员

# 安全
@app.route('/api/admin/users')
@admin_required
def list_users():
    return User.query.all()
```

```python
# 危险 - 响应含敏感字段
@app.route('/api/user/<id>')
def get_user(id):
    user = User.query.get(id)
    return jsonify(user.to_dict())  # password_hash, api_key 被一并返回

# 安全 - 使用序列化器
from marshmallow import Schema, fields

class UserSchema(Schema):
    class Meta:
        fields = ('id', 'username', 'email', 'created_at')
```

## OWASP 映射: A01/A03/A05/A07/A09
