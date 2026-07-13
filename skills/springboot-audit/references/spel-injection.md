# SpEL 注入 (CWE-917)

## 危险 sink

```java
import org.springframework.expression.spel.standard.SpelExpressionParser;

// ❌ 危险：表达式来自用户输入
SpelExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(userInput);
Object value = exp.getValue();
```

其他隐蔽形式：

- `@Value("#{ ${userProp} }")` — 属性值经 SpEL 解析
- `@PreAuthorize("hasRole('" + roleFromDb + "')")` — 拼接授权表达式
- Thymeleaf `th:text="${#object.getClass().getName()}"` 结合用户可控数据
- `MethodSecurityExpressionHandler` 自定义实现里拼接字符串

## 攻击 payload 骨架

```
T(java.lang.Runtime).getRuntime().exec("id")
new java.lang.ProcessBuilder("id").start()
T(org.springframework.cglib.core.ReflectUtils).defineClass(...)
```

## 修复建议

1. **不要用 SpEL 处理任意用户输入**。业务表达式请落到白名单。
2. 若必须使用，切换到 `SimpleEvaluationContext`（禁用类型引用 / 反射）：

```java
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
parser.parseExpression(templateExpr).getValue(ctx, rootObject);
```

3. `@PreAuthorize` 表达式必须为常量字面量，动态角色请走 `hasAuthority`
   + 参数绑定而不是字符串拼接。

## 相关规则

- Semgrep: `p/spring`, `p/java`
- 内建规则集：SB001 SpEL Injection
