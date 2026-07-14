---
name: spring-cloud-audit
version: 1.0.0
category: framework
description: Spring Cloud 微服务组件安全审计（Gateway / Config / Eureka / Feign）
author: DeepAudit
targets:
  languages: [java, kotlin]
  frameworks: [spring-cloud, spring-cloud-gateway, spring-cloud-config, eureka, feign, spring-cloud-openfeign, hystrix, resilience4j]
cwe_tags:
  - CWE-917  # SpEL Injection
  - CWE-918  # SSRF
  - CWE-306  # Missing Authentication
  - CWE-502  # Deserialization
  - CWE-284  # Improper Access Control
severity_focus: [critical, high]
tags: [spring-cloud, microservices, gateway, java, backend]
references:
  - references/gateway-spel-rce-cve-2022-22947.md
  - references/config-server-env-leak.md
  - references/eureka-unauthorized.md
  - references/feign-ssrf.md
scripts: []
---

# Spring Cloud 微服务安全审计

Spring Cloud 生态的漏洞多集中在：网关暴露 + 未鉴权 + 组件间 RPC 反序列化。
Gateway/Config/Eureka 三大件公网暴露 = 大概率灾难。

## 优先审计的攻击面

1. **Spring Cloud Gateway SpEL RCE — CVE-2022-22947 (CWE-917)** — 若启用 Actuator
   且 `management.endpoints.web.exposure.include=*`，`POST /actuator/gateway/routes/{id}`
   可注入包含 SpEL 的 filter，`refresh` 后触发。检测：Gateway 版本 ≤ 3.1.0 & Actuator 暴露。
2. **Spring Cloud Config Server /env 泄漏 (CWE-200)** — `spring.cloud.config.server.git.uri`
   指向公开仓库；`/env`、`/refresh` 未鉴权；`bootstrap.location` 支持 `${...}` 占位符
   注入。历史 CVE-2019-3799、CVE-2020-5405（路径穿越）。
3. **Eureka Server 未鉴权 (CWE-306)** — 默认端口 8761 无认证，`POST /eureka/apps/{app}`
   可注册恶意实例，服务发现流量重定向。检测：`spring.security.user` 未配置且
   `eureka.dashboard.enabled=true`。
4. **Feign / OpenFeign URL 拼接 SSRF (CWE-918)** — `@FeignClient(url = "${dynamic.url}")`
   或 `RequestLine("GET " + userInput)`。Feign contract 不做 URL 白名单。
5. **Ribbon 服务名劫持** — 若 `spring.cloud.loadbalancer.retry.enabled=true` 且
   服务发现未加密，攻击者注册同名服务夺流量。
6. **Hystrix Dashboard `/hystrix.stream` 未鉴权** — 泄漏内部服务拓扑与 QPS。
7. **Nacos 作为 Spring Cloud 注册中心** — 参见 `nacos-xxljob-audit` skill；
   `spring.cloud.nacos.discovery.username=nacos&password=nacos` 硬编码几乎必现。
8. **Sleuth / Zipkin trace-id 反注入** — HTTP header `X-B3-TraceId` 若透传到
   日志文件且未消毒，可写入日志伪造。

## 审计动作 checklist

- [ ] Gateway 版本 + Actuator 端点暴露列表
- [ ] Config Server 是否配置 Spring Security；`spring.cloud.config.server.git.uri` 是否 SSH+私仓
- [ ] Eureka `spring.security.user.*` / `eureka.client.registerWithEureka` 组合
- [ ] `@FeignClient` 与 `RequestLine` 中所有变量替换点
- [ ] `bootstrap.yml` 中所有 `${env.VAR}` 与 `${vault.…}` 引用链
- [ ] 服务间调用是否走 mTLS 或至少 Bearer Token 认证

## 参考文档

- `references/gateway-spel-rce-cve-2022-22947.md`
- `references/config-server-env-leak.md`
- `references/eureka-unauthorized.md`
- `references/feign-ssrf.md`
