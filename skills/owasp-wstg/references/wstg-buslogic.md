# WSTG-BUSLOGIC: 业务逻辑

## 检测清单

- [ ] 工作流可跳过/重放（多步骤流程步骤顺序绕过）
- [ ] 价格/金额可篡改（客户端传递价格、负值、溢出）
- [ ] 优惠券/折扣可重复使用
- [ ] 限额/配额绕过（速率限制条件竞争、重置）
- [ ] 状态机缺陷（订单状态异常转换）
- [ ] 用户枚举（注册/找回密码响应差异）
- [ ] 并发操作条件竞争（库存、余额、优惠券）
- [ ] 批量操作无总量限制
- [ ] 业务规则可绕过
- [ ] 日志审计缺失导致异常行为无法追溯

## 业务逻辑缺陷

```python
# 危险 - 客户端传递价格
@app.route('/checkout', methods=['POST'])
def checkout():
    price = request.form['price']           # 客户端可修改
    quantity = request.form['quantity']
    total = float(price) * int(quantity)
    # 安全：服务端计算价格

# 危险 - 负值攻击
def refund(user_id, amount):
    balance = get_balance(user_id)
    # 如果 amount 为负值，实际是加钱
    if amount > balance:
        return {"error": "余额不足"}
    update_balance(user_id, balance - amount)
```

```python
# 危险 - 优惠券竞态条件
def use_coupon(user_id, code):
    coupon = get_coupon(code)
    if coupon.remaining > 0:          # 此时另一个请求也通过了检查
        apply_discount(user_id, coupon)
        coupon.remaining -= 1         # 最后实际使用次数 > remaining

# 安全 - 使用数据库原子操作
def use_coupon(user_id, code):
    updated = db.execute("""
        UPDATE coupons SET remaining = remaining - 1
        WHERE code = ? AND remaining > 0
    """, (code,))
    if updated > 0:
        apply_discount(user_id, code)
```

## OWASP 映射: A01:2021 Broken Access Control
