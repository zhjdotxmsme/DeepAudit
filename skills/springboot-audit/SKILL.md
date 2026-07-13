---
name: springboot-audit
version: 1.0.0
category: framework
description: Spring Boot / Spring 生态安全审计知识包
author: DeepAudit
targets:
  languages: [java, kotlin]
  frameworks: [springboot, spring, spring-security, spring-cloud]
cwe_tags:
  - CWE-917  # SpEL injection
  - CWE-502  # Deserialization
  - CWE-16   # Configuration
  - CWE-352  # CSRF
  - CWE-284  # Access control
  - CWE-89   # SQL injection (JPA)
  - CWE-611  # XXE
severity_focus: [critical, high]
tags: [springboot, java, backend, api, jvm]
references:
  - references/spel-injection.md
  - references/actuator-exposure.md
  - references/deserialization.md
  - references/jpa-injection.md
scripts: []
---

# Spring Boot 安全审计

面向 Spring Boot / Spring 全家桶的专项审计知识，配合 DeepAudit Multi-Agent 使用。

## 优先审计的攻击面

按经验命中率从高到低：

1. **SpEL 注入 (CWE-917)** — `SpelExpressionParser.parseExpression(userInput)`、
   `@Value` / `@PreAuthorize` 表达式拼接、Thymeleaf `${...}` / `[[...]]` 拼接。
   一旦命中通常 = RCE。
2. **Actuator 端点暴露** — `management.endpoints.web.exposure.include=*` 或包含
   `env / heapdump / trace / mappings / jolokia / logfile`，等价于配置泄漏或 RCE。
3. **反序列化 (CWE-502)** — `ObjectInputStream.readObject`、Jackson `enableDefaultTyping`、
   Fastjson `parseObject(..., Object.class)`、XStream 未白名单。
4. **JPA / JPQL 注入 (CWE-89)** — `entityManager.createQuery("... " + input)`、
   `createNativeQuery("... " + input)`，注意 `@Query` 使用 `?1` 位置参数才是安全形式。
5. **访问控制缺失 (CWE-284)** — Controller 没有 `@PreAuthorize` / `@Secured`；
   `SecurityConfig` 里 `permitAll()` 覆盖了敏感路径；`WebSecurityCustomizer.ignoring()`
   完全放行了业务接口而非静态资源。
6. **JNDI 注入 / SSRF** — `InitialContext.lookup`、`RestTemplate` / `WebClient`
   接收用户可控 URL 无白名单。
7. **CORS 配置错误** — `Access-Control-Allow-Origin: *` 与 `Allow-Credentials: true` 组合；
   `addAllowedOriginPattern("*")` 在生产。
8. **Mass Assignment** — Controller 直接接收 `@RequestBody Entity` 而非 DTO，允许
   攻击者伪造 `id`、`role`、`isAdmin` 等字段。

## 审计动作 checklist

对每个 Controller / Service：

- [ ] 入参是否来自 `@RequestParam` / `@PathVariable` / `@RequestBody` 且未校验？
- [ ] 是否流向以下 sink：`SpelExpressionParser`、`Runtime.exec`、
      `ProcessBuilder`、`ObjectInputStream`、`createQuery("... " + x)`、
      `RestTemplate.getForObject(x, …)`、`InitialContext.lookup(x)`？
- [ ] 是否覆盖了 `@PreAuthorize` / `@Secured` / 方法级授权？
- [ ] 敏感字段是否走了 DTO 而非直接绑定 Entity？

## 参考文档

- `references/spel-injection.md` — SpEL 注入检测细节 + 修复建议
- `references/actuator-exposure.md` — Actuator 白名单最佳实践
- `references/deserialization.md` — 反序列化各库黑白名单
- `references/jpa-injection.md` — JPA 参数化查询模板
