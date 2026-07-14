---
name: nacos-xxljob-audit
version: 1.0.0
category: middleware
description: Nacos 配置中心与 XXL-Job 任务调度组件安全审计
author: DeepAudit
targets:
  languages: [java, kotlin, yaml, properties]
  frameworks: [nacos, xxl-job, xxl-job-executor, xxl-job-admin, spring-cloud-alibaba]
cwe_tags:
  - CWE-306  # Missing Authentication
  - CWE-798  # Hardcoded Credentials
  - CWE-502  # Deserialization
  - CWE-284  # Access Control
  - CWE-88   # Argument Injection
severity_focus: [critical, high]
tags: [nacos, xxljob, middleware, java, rce]
references:
  - references/nacos-auth-bypass.md
  - references/nacos-default-creds.md
  - references/xxljob-executor-rce.md
  - references/xxljob-hessian-deser.md
scripts: []
---

# Nacos / XXL-Job 中间件安全审计

Nacos 与 XXL-Job 是 Java 企业内部最常见的两个"打进就 RCE"的组件，历史 CVE 密集，
默认配置几乎全部不安全。审计重点：默认口令、鉴权关闭、Hessian 反序列化。

## Nacos 攻击面

1. **默认口令 nacos:nacos (CWE-798)** — Nacos ≤ 2.2.x 默认账号，登录后
   `/nacos/v1/cs/configs` 可读写任意配置。检测：`nacos.core.auth.plugin.nacos.token.secret.key`
   若为默认 `SecretKey012345678901234567890123456789012345678901234567890123456789`。
2. **User-Agent 绕过鉴权 (CWE-287) — CVE-2021-29441** — 请求带 `User-Agent: Nacos-Server`
   跳过 auth filter，可直接访问 `/nacos/v1/auth/users` 创建管理员。修复版本 1.4.1+。
3. **auth.enabled=false (CWE-306)** — `nacos.core.auth.enabled=false` 全放开。
   配置文件 & 环境变量都要检查。
4. **JWT secret key 弱** — `nacos.core.auth.plugin.nacos.token.secret.key` 长度不足或
   全网可搜索。Nacos 2.2.1 后强制要求 base64 编码 ≥ 32 字节。
5. **配置中心加密插件缺失** — 数据库密码、AK/SK 明文存 Nacos，dataId 一览无余。
6. **derby 未授权 SQL 注入 — CVE-2020-3116** — `/nacos/v1/cs/ops/derby?sql=…`。
7. **contextPath 绕过 — CVE-2021-29442** — 未鉴权访问 `/nacos/v1/cs/ops/data/removal`。

## XXL-Job 攻击面

1. **Executor 端口 9999 未鉴权 (CWE-306)** — 默认 `xxl.job.accessToken` 为空，
   `/run` POST GLUE 类型任务可直接执行 shell / Java 代码 = RCE。
2. **`accessToken` 硬编码或默认 (CWE-798)** — 常见默认 `default_token`，或代码库中
   `properties` 明文。Executor 与 Admin 共享同一 token。
3. **Hessian 反序列化 — CVE-2022-43183 / CVE-2023-XXX (CWE-502)** — Admin 端 `/api/registry`
   接收 Hessian2 序列化对象，无白名单类过滤，链: `SignObject → ROME → JdbcRowSet` 等。
4. **GLUE 源码存 DB (CWE-284)** — 若 Admin 被打穿，历史 GLUE 代码可查询到，
   蓝队清理时容易漏。
5. **`/xxl-job-admin/jobinfo/add` 参数注入** — `executorParam` 拼接到 shell/Java glue，
   相当于 argument injection (CWE-88)。

## 审计动作 checklist

- [ ] Nacos `application.properties`：`nacos.core.auth.enabled`、`token.secret.key`、
      `plugin.nacos.token.expire.seconds`
- [ ] Nacos 版本号（1.4.1、2.1.1、2.2.1 是关键分水岭）
- [ ] XXL-Job `xxl.job.accessToken` 是否为空、默认值或版本控制中泄漏
- [ ] Executor 是否只监听 127.0.0.1 或走 mTLS
- [ ] 生产是否禁用 GLUE 类型任务（改用 Bean 类型）
- [ ] `xxl-job-admin` 版本（≤ 2.3.1 有 Hessian 反序列化）

## 参考文档

- `references/nacos-auth-bypass.md`
- `references/nacos-default-creds.md`
- `references/xxljob-executor-rce.md`
- `references/xxljob-hessian-deser.md`
