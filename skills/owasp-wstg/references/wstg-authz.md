# WSTG-AUTHZ: 授权

## 检测清单

- [ ] 水平越权（IDOR - 可访问同级别其他用户数据）
- [ ] 垂直越权（普通用户可执行管理员操作）
- [ ] 功能级访问控制缺失
- [ ] HTTP 方法绕过权限（POST→GET 绕过鉴权）
- [ ] 参数篡改可提升权限
- [ ] API 批量操作无权限验证
- [ ] 文件操作无所有权验证
- [ ] 多步骤流程中步骤跳过

## IDOR 常见模式

```python
# 危险 - 仅依赖用户参数
@app.route('/api/user/<user_id>/profile')
def get_profile(user_id):
    user = db.query(User).get(user_id)  # 未验证当前用户 == user_id
    return user.to_dict()

# 安全 - 验证所有权
@app.route('/api/user/<user_id>/profile')
def get_profile(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        return {"error": "forbidden"}, 403
    user = db.query(User).get(user_id)
    return user.to_dict()
```

```java
// Spring Security 方法级权限
@PreAuthorize("#userId == authentication.principal.id or hasRole('ADMIN')")
public User getUser(@PathVariable Long userId) {
    return userService.findById(userId);
}
```

## OWASP 映射: A01:2021 Broken Access Control
