---
name: owasp-wstg
description: |
  OWASP Web Security Testing Guide (WSTG) security audit skill.
  Covers all 12 WSTG categories for comprehensive web application and
  database security testing. Integrates OWASP Top 10 2021 mapping for
  every vulnerability class.
  Language-agnostic detection patterns with language-specific examples
  for Java, Python, Go, PHP, JavaScript/TypeScript, C#/.NET, Ruby.
  Covers traditional web, API (REST/GraphQL/gRPC), database (SQL/NoSQL/ORM),
  configuration, cryptography, business logic, and client-side security.
tools:
  - Read
  - Grep
  - Glob
  - Bash
model: sonnet
priority: high
file_patterns:
  - "**/*.py"
  - "**/*.js"
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.jsx"
  - "**/*.java"
  - "**/*.go"
  - "**/*.php"
  - "**/*.rb"
  - "**/*.cs"
  - "**/*.rs"
  - "**/*.sql"
  - "**/*.xml"
  - "**/*.yml"
  - "**/*.yaml"
  - "**/*.json"
  - "**/*.properties"
  - "**/*.env"
  - "**/Dockerfile"
  - "**/*.tf"
  - "**/*.graphql"
  - "**/*.proto"
exclude_patterns:
  - "**/node_references/**"
  - "**/vendor/**"
  - "**/dist/**"
  - "**/build/**"
  - "**/target/**"
  - "**/.git/**"
  - "**/test/**"
  - "**/tests/**"
  - "**/__pycache__/**"
  - "**/.next/**"
  - "**/node_modules/**"
---

# OWASP Web Security Testing Guide (WSTG) 技能

> 基于 OWASP WSTG v5.0 的全量 Web + 数据库安全审计技能

## 使用方式

执行审计时先运行 `list_wstg_checks()` 确定当前项目应适用的 WSTG 测试范围，
再按类别逐项检查。

## WSTG 类别一览

| 缩写 | 类别 | OWASP Top 10 | 引用文件 |
|------|------|-------------|---------|
| INFO | 信息收集 | — | references/wstg-info-gathering.md |
| CONFIG | 配置管理 | A05/A06 | references/wstg-config.md |
| IDENT | 身份认证 | A07 | references/wstg-ident.md |
| AUTHZ | 授权 | A01 | references/wstg-authz.md |
| SESS | 会话管理 | A07 | references/wstg-sess.md |
| INPV | 输入验证 | A03 | references/wstg-input.md |
| CRYPST | 密码学 | A02 | references/wstg-crypto.md |
| BUSLOGIC | 业务逻辑 | A01 | references/wstg-buslogic.md |
| CLIENT | 客户端安全 | A03 | references/wstg-client.md |
| API | API 安全 | A01/A03/A05/A07/A09 | references/wstg-api.md |
| DB | 数据库安全 | A03/A04/A06/A09 | references/wstg-database.md |

## 执行指南

1. **信息收集阶段**: 识别技术栈、端点、认证方式、数据库类型
2. **配置审计**: 检查默认配置、调试端点、CORS、安全头
3. **身份认证**: OAuth/SSO/JWT/Session 认证机制审计
4. **授权检查**: IDOR、RBAC 绕过、水平/垂直提权
5. **会话安全**: CSRF、Session Fixation、Cookie 属性
6. **输入验证**: SQL/NoSQL/命令/SSRF/XXE/模板注入（核心）
7. **密码学**: TLS 配置、弱算法、Padding Oracle、证书验证
8. **业务逻辑**: 工作流滥用、限额绕过、支付篡改、状态机缺陷
9. **客户端**: DOM XSS、CSP、PostMessage、LocalStorage
10. **API 安全**: REST/GraphQL/gRPC 鉴权、批量漏洞、深度分页
11. **数据库安全**: 存储过程注入、HQL/JPQL、盲注、提权、审计日志

## 参考

- OWASP WSTG v5.0: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 2021: https://owasp.org/Top10/
- 各 WSTG 分类测试清单见 `references/` 目录
