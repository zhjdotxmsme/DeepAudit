# Feign / OpenFeign SSRF

## 攻击面

Feign 客户端把注解方法编译成 HTTP 请求。若 URL 或 path 参数来自用户输入且拼接构造，
等价于 Java 后端里的 `RestTemplate.getForObject(userUrl, ...)`。

## 危险模式

### 1. `@FeignClient(url = "${dynamic}")`

```java
@FeignClient(name = "downstream", url = "${downstream.url}")
public interface DownstreamClient {
    @GetMapping("/data")
    String getData();
}
```

如果 `downstream.url` 来自 Nacos / Config Server 且配置项攻击者可写 → 内部服务被打成
SSRF 跳板。

### 2. `@RequestLine` 拼接

```java
public interface OpenApiClient {
    @RequestLine("GET " + BASE_URL + "/api")   // 编译期常量还好
    String fetch();
}

// ❌ 危险：程序化构造 URL
Feign.builder().target(SomeClient.class, "http://" + host + ":" + port);
```

### 3. `@PathVariable` 未编码

```java
@GetMapping("/proxy/{url}")
String proxy(@PathVariable("url") String url);
```

调用方传 `url = "internal:8080/admin"` → Feign 内部拼路径未做校验 = SSRF。

### 4. URL 参数直接透传

```java
@FeignClient(...)
public interface Client {
    @GetMapping
    String get(URI uri);  // URI 由 caller 完全控制
}

// caller
client.get(URI.create(userInput));
```

## 修复

### 白名单 downstream host

```java
private static final Set<String> ALLOWED_HOSTS = Set.of(
    "user-service", "order-service"
);

public String callDownstream(String service) {
    if (!ALLOWED_HOSTS.contains(service)) {
        throw new IllegalArgumentException();
    }
    return client.getByService(service);
}
```

### 走服务发现而非 URL

```java
@FeignClient(name = "user-service")  // 从 Eureka/Nacos 解析
```

不要用 `url =` 属性硬编码或动态化。

### `RequestInterceptor` 校验

```java
public class SSRFInterceptor implements RequestInterceptor {
    @Override
    public void apply(RequestTemplate template) {
        String url = template.feignTarget().url();
        if (!isAllowed(url)) {
            throw new IllegalStateException("Blocked SSRF: " + url);
        }
    }
}
```

## 审计动作

- [ ] 所有 `@FeignClient` 的 `url` 属性来源
- [ ] `Feign.builder().target()` 调用
- [ ] `RequestLine` / `RequestMapping` 中 `${}` 占位符
- [ ] 是否有 `RequestInterceptor` 做 host 白名单

## 相关规则

- CWE: CWE-918 (SSRF)
- 内建 pattern: `java_ssrf`
- Semgrep: `p/java`, `r/java.spring.security`
