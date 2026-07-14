# MyBatis-Plus QueryWrapper / LambdaQueryWrapper 危险 API

## 概览

MyBatis-Plus 提供 QueryWrapper 抽象层，多数 API（`eq/lt/gt/like` 等）是安全的（走参数绑定）。
但以下 API **第一参数是 SQL 片段字符串**，直接拼进 SQL：

| API | 参数 | 风险 |
|-----|-----|------|
| `apply(String, Object...)` | 首参 SQL 片段 | ⚠️ 极高 |
| `last(String)` | 追加到 SQL 末尾 | ⚠️ 极高 |
| `orderByAsc(String)` / `orderByDesc(String)` (String 版本) | 列名字符串 | ⚠️ 高 |
| `having(String, Object...)` | 首参 SQL 片段 | ⚠️ 高 |
| `groupBy(String)` (String 版本) | 列名字符串 | ⚠️ 高 |
| `select(String)` (String 版本) | 列名列表字符串 | ⚠️ 中 |
| `inSql(String, String)` | 首参列名 + 次参子查询 SQL | ⚠️ 高 |
| `notInSql(String, String)` | 同上 | ⚠️ 高 |
| `exists(String)` | 子查询 SQL | ⚠️ 高 |
| `notExists(String)` | 子查询 SQL | ⚠️ 高 |

## 危险示例

```java
// ❌ apply 首参拼接
QueryWrapper<User> wrapper = new QueryWrapper<>();
wrapper.apply("date_format(create_time, '${format}') = {0}", userFormat, dateValue);
// ${format} 已被字面替换到 SQL 中！{0} 才走参数绑定。

// ❌ last 直接追加
wrapper.last("ORDER BY " + userOrderBy);

// ❌ orderBy 字符串
wrapper.orderByAsc(userColumn);

// ❌ inSql 拼接子查询
wrapper.inSql("id", "SELECT id FROM t WHERE name = '" + userName + "'");
```

## 安全替代

```java
// ✅ 使用 Lambda 版本，列名走 SFunction 反射
LambdaQueryWrapper<User> lambda = new LambdaQueryWrapper<>();
lambda.eq(User::getName, name);          // 参数绑定
lambda.orderByAsc(User::getCreateTime);  // 列名编译期确定

// ✅ apply 只用 {0} {1} 参数占位
wrapper.apply("date_format(create_time, '%Y-%m-%d') = {0}", dateStr);

// ✅ inSql 用参数化子查询
List<Long> ids = otherMapper.selectIds(name);
wrapper.in("id", ids);
```

## 自定义方法注入（InjectionMethod）

MyBatis-Plus 允许通过 `AbstractMethod` 子类注入自定义 SQL 方法，模板 `SqlSource`
中使用 `${}` 时若参数最终可控，同样是注入面。审计自定义 `SqlInjector` 实现类。

## 审计动作

```bash
grep -rn '\.apply\|\.last\|\.inSql\|\.notInSql\|\.exists\|\.notExists\|\.having' src/main/java/ | grep -v test
```

对每个匹配点：

- 首参是否含用户输入？
- 是否走 String 拼接？

## 相关规则

- CWE: CWE-89
- 内建 pattern: `mybatis_dollar_injection`
