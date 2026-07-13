# JPA / JPQL / 原生 SQL 注入

## 危险模式

```java
// ❌ 字符串拼接
String jpql = "SELECT u FROM User u WHERE u.name = '" + name + "'";
entityManager.createQuery(jpql, User.class).getResultList();

// ❌ 原生 SQL 拼接
entityManager.createNativeQuery("SELECT * FROM users WHERE name='" + name + "'").getResultList();

// ❌ Spring Data @Query 使用字符串格式化而非位置/命名参数
@Query("SELECT u FROM User u WHERE u.role = '" + "#{#role}" + "'")
```

## 安全模式

```java
// ✅ 命名参数
String jpql = "SELECT u FROM User u WHERE u.name = :name";
entityManager.createQuery(jpql, User.class)
             .setParameter("name", name)
             .getResultList();

// ✅ Spring Data @Query 位置参数
@Query("SELECT u FROM User u WHERE u.role = ?1")
List<User> findByRole(String role);

// ✅ 或命名参数 @Param
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);
```

## 常见误区

- `@Query(nativeQuery = true)` **不会**自动参数化，仍需用 `?1` / `:name`。
- Criteria API 里通过 `builder.literal(userInput)` 传入用户值等价于拼接，
  应使用 `ParameterExpression`。
- `ORDER BY` 字段名不能参数化，如需支持动态排序请白名单校验列名。

## 修复 checklist

- [ ] 所有 `createQuery` / `createNativeQuery` 调用是否零字符串拼接？
- [ ] `@Query` 注解内容为静态 JPQL/SQL，用户输入通过 `?n` / `:name` 绑定？
- [ ] 动态列名 / 排序方向经过白名单枚举？
