# Spring Boot Actuator 暴露

## 危险配置

```yaml
# ❌ 危险：暴露所有端点
management:
  endpoints:
    web:
      exposure:
        include: "*"
```

或 properties：

```
management.endpoints.web.exposure.include=*
management.endpoint.env.enabled=true
management.endpoint.heapdump.enabled=true
```

高危端点：

| 端点 | 后果 |
|------|------|
| `/actuator/env` | 环境变量 + 配置泄漏（含数据库密码、云 AK） |
| `/actuator/heapdump` | 堆转储，可从中提取密码、Token |
| `/actuator/jolokia` | JMX HTTP 桥，可 RCE |
| `/actuator/logfile` | 日志文件泄漏 |
| `/actuator/mappings` | 完整路由清单，攻击面测绘 |
| `/actuator/threaddump` | 线程栈，泄漏内部方法调用 |
| `/actuator/gateway/routes` | Spring Cloud Gateway 未鉴权时可导致 RCE |

## 修复建议

1. 生产环境 **只暴露 `health` 和 `info`**：

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
      base-path: /internal/actuator   # 换基路径
  endpoint:
    health:
      show-details: never
```

2. 若需完整 actuator，务必：
   - 走独立管理端口 `management.server.port=9090`
   - 独立鉴权（Spring Security 单独配置 `/actuator/**` requireAuthorization）
   - 反向代理层禁止外部访问该端口

3. 特别注意 Spring Cloud Gateway 的 `/actuator/gateway/refresh` 与
   `/actuator/gateway/routes/{id}`：CVE-2022-22947 的锅仍然会以配置错误的形式出现。
