# ORDER BY / LIMIT / IN 无法参数化的注入面

## 为什么 `#{}` 不能用于 ORDER BY

`#{}` 走 PreparedStatement，JDBC 会对参数值加引号：

```sql
-- MyBatis 生成
SELECT * FROM t ORDER BY ?
-- 传入 orderBy = "name"，实际执行
SELECT * FROM t ORDER BY 'name'   -- 语法错误或按字面量常量排序
```

因此 ORDER BY / LIMIT / 表名 / 列名必须走文本替换 = `${}` = 危险。

## 常见误用

```xml
<!-- ❌ 前端直接传 orderBy -->
<select id="list">
    SELECT * FROM users ORDER BY ${orderBy} ${orderDir}
</select>
```

payload：`orderBy = "id;DELETE FROM users--"` 或
`orderBy = "IF((SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a',SLEEP(5),0)"` (盲注).

## 安全实现方案

### 方案 A：枚举白名单

```java
private static final Map<String, String> ORDER_MAP = Map.of(
    "id", "id",
    "name", "name",
    "createTime", "create_time"
);
private static final Set<String> DIRECTIONS = Set.of("ASC", "DESC");

public List<User> list(String orderBy, String direction) {
    String col = ORDER_MAP.get(orderBy);
    if (col == null) col = "id";
    String dir = DIRECTIONS.contains(direction.toUpperCase()) ? direction : "ASC";
    return mapper.list(col, dir);
}
```

Mapper 内可以 `ORDER BY ${col} ${dir}`（已被白名单严格约束）。

### 方案 B：MyBatis-Plus `OrderItem`

```java
Page<User> page = new Page<>(1, 10);
page.addOrder(OrderItem.asc(escapeColumn(orderBy)));
```

`escapeColumn` 内部实现白名单校验。

### 方案 C：ANTLR / JSqlParser 解析

对 orderBy 表达式做 SQL AST 解析，禁止函数调用、子查询、逗号后附加语句。

## LIMIT / OFFSET

```java
// ❌ 危险
"LIMIT " + pageSize + " OFFSET " + offset

// ✅ 强制转 int 后拼接
int limit = Math.min(Math.max(pageSize, 1), 100);
int offset = Math.max(page * limit, 0);
```

`Integer.parseInt` 抛异常等价于校验；但传入负数需另加保护。

## `IN (...)` 列表

```xml
<!-- ✅ 使用 <foreach> + #{} -->
<select id="listByIds">
    SELECT * FROM t WHERE id IN
    <foreach collection="ids" item="id" open="(" separator="," close=")">
        #{id}
    </foreach>
</select>
```

## 相关规则

- CWE: CWE-89
- 内建 pattern: `mybatis_dollar_injection`
- PageHelper `startPage(1, 10, orderBy)` 第三参走 ${}，等价危险
