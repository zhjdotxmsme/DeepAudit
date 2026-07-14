---
name: java-deser-audit
version: 1.0.0
category: vulnerability-class
description: Java 反序列化 / JNDI 注入专项审计（Fastjson / Jackson / Shiro / Hessian / Log4Shell）
author: DeepAudit
targets:
  languages: [java, kotlin]
  frameworks: [fastjson, fastjson2, jackson, shiro, hessian, dubbo, log4j, log4j2, xstream, snakeyaml]
cwe_tags:
  - CWE-502  # Deserialization of Untrusted Data
  - CWE-917  # SpEL Injection
  - CWE-74   # Injection
  - CWE-77   # Command Injection
severity_focus: [critical, high]
tags: [deserialization, jndi, java, rce, gadget]
references:
  - references/fastjson-autotype.md
  - references/jackson-defaulttyping.md
  - references/shiro-rememberme.md
  - references/hessian2-dubbo.md
  - references/log4shell-jndi.md
scripts: []
---

# Java 反序列化 / JNDI 注入审计

Java 反序列化十几年来一直是"打进就是 root"的头号沉洞。审计核心：不看是否受信输入，
看**是否允许类型引用**。任何 `Object.class` / `enableDefaultTyping` / `autoType` /
`readObject` 出现在数据边界都是致命。

## 通用检测原则

**危险 = 输入可控 + 类型可选 + gadget 可达**

- 输入可控：HTTP body / Header / Cookie / MQ / RPC
- 类型可选：反序列化器允许根据 JSON `@type`、`class` 字段决定实例类
- gadget 可达：classpath 中存在已知 gadget（Fastjson JdbcRowSetImpl、CommonsCollections、
  Rome、C3P0、Groovy…）

## 各库审计要点

### Fastjson 1.2.x
- `JSON.parseObject(str)` **无第二参** → 依赖 `@type` 字段，autoType 开启即 RCE
- `JSON.parseObject(str, Object.class)` / `.parse(str)` 同样危险
- `ParserConfig.getGlobalInstance().setAutoTypeSupport(true)` 显式打开
- 高危 payload：`{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://..."}`
- 修复：升级 1.2.83 起走 safeMode，或 Fastjson2

### Fastjson2
- 默认关闭 autoType，但 `Feature.SupportAutoType` 或 `JSONReader.Feature.SupportClassForName` 打开即回归
- `JSONB.parseObject(bytes, ...)` 二进制格式易被漏审

### Jackson (jackson-databind)
- `objectMapper.enableDefaultTyping()` = 灾难
- `enableDefaultTyping(NON_FINAL)`、`activateDefaultTyping(LaissezFaireSubTypeValidator)` 同样危险
- `@JsonTypeInfo(use = Id.CLASS)` 加在 Object 类型字段上等于给 gadget 开口
- 版本流转关键：2.9.10.x → 2.14.x 大量 gadget blacklist 演进；黑名单永远追不上

### Shiro
- `cookie.rememberMe.cipherKey` 默认 `kPH+bIxk5D2deZiIxcaaaA==` (base64 of `2AvVhdsgUs0FSA3SDFAdag==`)
- Shiro < 1.2.5 硬编码；≥ 1.2.5 允许自定义但很多项目未改
- Shiro < 1.7.0 路径穿越 `/xxx/..;/admin` 绕过鉴权 filter
- Shiro < 1.9.2 CVE-2022-32532 RegExPatternMatcher 正则绕过

### Hessian2 / Dubbo
- Dubbo 默认协议 hessian2 无类型白名单 → CVE-2021-25641 / CVE-2023-23638
- 检测：`<dubbo:protocol name="hessian" />` 或 `<dubbo:reference protocol="hessian" />`
- 修复：升级到 Dubbo 3.2+ 并开启 `dubbo.application.serialize-check-status=STRICT`

### Log4Shell (Log4j2)
- `${jndi:ldap://...}` 出现在被 log4j 记录的任何字符串 = RCE
- 检测：Log4j 版本 ≤ 2.14.1；`log4j2.formatMsgNoLookups=true` 是否设置
- 隐蔽点：User-Agent、Referer、Cookie、异常堆栈 message

### XStream / SnakeYAML
- XStream 默认允许类型引用，需白名单
- SnakeYAML `new Yaml().load(userInput)` 允许 `!!javax.script.ScriptEngineManager` gadget

## 审计动作 checklist

- [ ] 依赖树全量 grep：`fastjson`、`jackson-databind`、`shiro-core`、
      `dubbo`、`log4j-core`、`xstream`、`snakeyaml`、`hessian`
- [ ] 每处反序列化调用点：查 gadget 白名单/黑名单是否设置
- [ ] `ObjectMapper` 全局单例是否配置了 `deactivateDefaultTyping`
- [ ] Shiro `SecurityUtils.setSecurityManager` 附近查 `CookieRememberMeManager.setCipherKey`
- [ ] `application.yml` / `bootstrap.yml` 中所有 dubbo/hessian 协议出现
- [ ] Log4j 版本 & `log4j2.formatMsgNoLookups` JVM 参数

## 参考文档

- `references/fastjson-autotype.md`
- `references/jackson-defaulttyping.md`
- `references/shiro-rememberme.md`
- `references/hessian2-dubbo.md`
- `references/log4shell-jndi.md`
