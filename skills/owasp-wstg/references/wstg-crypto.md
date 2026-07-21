# WSTG-CRYPST: 密码学

## 检测清单

- [ ] 敏感信息未加密传输（HTTP、未启用 TLS）
- [ ] TLS 配置弱（TLS 1.0/1.1、弱密码套件）
- [ ] 弱加密算法使用（MD5、SHA1、RC4、DES、3DES）
- [ ] 弱密钥生成（硬编码、可预测、短密钥）
- [ ] 密码存储未使用专门哈希（bcrypt/argon2/scrypt）
- [ ] ECB 模式使用（块加密中泄露模式信息）
- [ ] Padding Oracle 漏洞（CBC 模式中允许填充校验）
- [ ] 随机数生成使用不安全种子（random 而非 secrets）
- [ ] 证书验证跳过（verify=False, SSL_CERT_FILE 未设置）
- [ ] JWT 密钥硬编码或可猜测

## 密码存储

```python
# 危险
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# 安全 - bcrypt
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 安全 - argon2
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)
```

## TLS 证书验证

```python
import requests

# 危险 - 跳过证书验证
resp = requests.get(url, verify=False)  # MITM 可截获

# 安全
resp = requests.get(url, verify=True)
```

## OWASP 映射: A02:2021 Cryptographic Failures
