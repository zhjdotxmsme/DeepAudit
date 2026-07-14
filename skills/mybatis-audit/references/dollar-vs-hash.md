# `${}` vs `#{}` — MyBatis 参数替换机制

## 核心差异

| 语法 | 机制 | SQL 类型 | 是否安全 |
|------|------|---------|---------|
| `#{name}` | JDBC PreparedStatement 参数绑定 | 值位 (`WHERE col = ?`) | ✅ 安全 |
| `${name}` | MyBatis 文本替换 | 任意位（SQL 关键字/表名/列名） | ❌ 危险 |

`#{}` 生成的 SQL 中，参数是 `?` 占位符，最终由 JDBC 走 PreparedStatement.setXxx。
`${}` 直接把参数值以字符串形式拼进 SQL 语句，等价于 Java `"..." + userInput + "..."`。

## 危险示例

```xml
<!-- ❌ 危险 -->
<select id="findByName" resultType="User">
    SELECT * FROM users WHERE name = '${name}'
</select>
```

传入 `name = "admin' OR '1'='1"` → 全表返回。

```java
// ❌ 危险
@Select("SELECT * FROM users WHERE role = '${role}'")
List<User> findByRole(@Param("role") String role);
```

## 安全写法

```xml
<!-- ✅ 安全 -->
<select id="findByName" resultType="User">
    SELECT * FROM users WHERE name = #{name}
</select>
```

```java
// ✅ 安全
@Select("SELECT * FROM users WHERE role = #{role}")
List<User> findByRole(@Param("role") String role);
```

## 什么时候必须用 `${}`

`#{}` 不能用于 SQL 关键字位（表名、列名、ORDER BY、LIMIT）。此时必须走白名单：

```java
private static final Set<String> ALLOWED_COLUMNS = Set.of("id", "name", "create_time");

public List<User> listSorted(String orderBy) {
    if (!ALLOWED_COLUMNS.contains(orderBy)) {
        throw new IllegalArgumentException("Invalid orderBy: " + orderBy);
    }
    return mapper.listSorted(orderBy);  // 此时才允许 ${orderBy}
}
```

或用 MyBatis-Plus `SqlHelper` / `SqlKeyword.escape` 做转义。

## 相关规则

- 内建 pattern: `mybatis_dollar_injection`
- Semgrep: `p/java`, `r/java.mybatis`
- CWE: CWE-89, CWE-943
