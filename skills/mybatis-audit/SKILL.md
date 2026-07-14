---
name: mybatis-audit
version: 1.0.0
category: orm
description: MyBatis / MyBatis-Plus SQL 注入与动态 SQL 审计知识包
author: DeepAudit
targets:
  languages: [java, kotlin, xml]
  frameworks: [mybatis, mybatis-plus, mybatis-spring, tk-mybatis]
cwe_tags:
  - CWE-89   # SQL Injection
  - CWE-564  # SQL Injection: Hibernate/ORM
  - CWE-943  # Improper Neutralization of Special Elements in Data Query Logic
severity_focus: [critical, high]
tags: [mybatis, orm, java, sql, injection]
references:
  - references/dollar-vs-hash.md
  - references/xml-fragment-injection.md
  - references/orderby-injection.md
  - references/mybatis-plus-wrapper.md
scripts: []
---

# MyBatis SQL 注入审计

MyBatis 家族的 SQL 注入几乎全部源于 `${}` 与 `#{}` 使用不当。`#{}` 走 PreparedStatement
参数绑定，`${}` 是纯文本替换。任何 `${userInput}` 出现在 SQL 中都是可疑点。

## 优先审计的攻击面

1. **`${}` 直接拼接用户输入 (CWE-89)** — Mapper 接口 `@Select("SELECT * FROM t WHERE name='${name}'")`
   或 XML `<select>SELECT * FROM t WHERE name='${name}'</select>`。即使参数是字符串类型
   也走文本替换。攻击者可 `' OR 1=1--`。
2. **`ORDER BY / LIMIT` 无法用 `#{}` 参数化 (CWE-89)** — 因这两处是 SQL 关键字位而非值位。
   常见错误写法 `ORDER BY ${orderBy}`。必须走白名单校验（枚举列名）或 ANTLR 解析。
3. **`<sql>` 片段拼接 (CWE-89)** — `<sql id="cond">... ${where}</sql>` 通过 `<include>`
   引入，`where` 参数经外层传入若未净化即注入。
4. **动态标签内嵌 `${}` (CWE-89)** — `<if test="type != null">AND type='${type}'</if>`；
   `<foreach>` 里 `#{item}` 是安全的，`${item}` 危险。
5. **`@SelectProvider` / `SqlBuilder`** — 通过 Java 拼接 SQL 字符串再返回给
   MyBatis 执行，本质是 String concatenation，最易被漏审。
6. **MyBatis-Plus `QueryWrapper.apply(String, Object...)`** — `apply("date_format(create_time,'${format}') = {0}", date)`
   第一参是 SQL 片段直拼，第二个才是参数。同类：`last()`、`orderByAsc/Desc(String)` 传字符串列名。
7. **`typeHandler` / 二级缓存反序列化** — 自定义 `TypeHandler` 若在 `getResult` 中
   `readObject` 未白名单化，可触发 Java 反序列化 RCE。
8. **PageHelper `startPage(pageNum, pageSize, orderBy)` 第三参** — 直接拼接到 `ORDER BY`
   后，若来自前端等于注入。

## 审计动作 checklist

对每个 Mapper 文件（`.java` 接口 + `.xml`）：

- [ ] `grep -rn '\${' src/main/resources/mapper/` 全部人工过
- [ ] `@Select` / `@Update` / `@Delete` / `@Insert` 注解中含 `${` 的位置
- [ ] `orderBy` / `sort` / `column` 参数是否走枚举白名单
- [ ] `QueryWrapper.apply` / `last` / `having` 的字符串来源
- [ ] `<sql>` 片段与 `<include>` 传参链路
- [ ] MyBatis-Plus 自定义 SQL 注入方法（`InjectionMethod` 子类）

## 参考文档

- `references/dollar-vs-hash.md` — `${}` vs `#{}` 详细差异
- `references/xml-fragment-injection.md` — `<sql>` 片段与 `<include>` 传参陷阱
- `references/orderby-injection.md` — ORDER BY / LIMIT 白名单实现
- `references/mybatis-plus-wrapper.md` — QueryWrapper / LambdaQueryWrapper 危险 API
