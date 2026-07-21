"""
易受攻击和过时的组件 (A06:2021) 漏洞知识

OWASP Top 10 A06:2021 — Vulnerable and Outdated Components
"""

from ..base import KnowledgeDocument, KnowledgeCategory


VULNERABLE_COMPONENTS = KnowledgeDocument(
    id="vuln_vulnerable_components",
    title="易受攻击和过时的组件",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["dependencies", "outdated", "components", "supply-chain", "sbom", "patching"],
    severity="high",
    cwe_ids=["CWE-1104", "CWE-937", "CWE-1035"],
    owasp_ids=["A06:2021"],
    content="""
# 易受攻击和过时的组件

## 概述

使用已知漏洞的组件是应用安全最常见的问题之一。现代应用大量依赖开源组件和第三方库，
版本管理不当会导致已知漏洞被直接引入生产环境。

## 漏洞模式

### 1. 直接依赖已知漏洞版本

```json
// package.json - 使用已知漏洞版本
{
  "dependencies": {
    "lodash": "^4.17.15",       // 已知CVE
    "express": "4.16.0",        // 已知漏洞
    "axios": "0.19.0"
  }
}
```

```xml
<!-- pom.xml - 使用过时组件 -->
<dependency>
    <groupId>log4j</groupId>
    <artifactId>log4j</artifactId>
    <version>1.2.17</version>  <!-- Log4Shell 等漏洞 -->
</dependency>
```

```python
# requirements.txt - 未锁定版本
requests>=2.0.0       # 可能引入不兼容或含漏洞版本
flask>=1.0
```

### 2. 传递性依赖引入漏洞

```xml
<!-- pom.xml - SnakeYAML 通过其他依赖引入 -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.5.3</version>  <!-- 间接依赖已知漏洞的 snakeyaml -->
</dependency>
```

### 3. 容器基础镜像过时

```dockerfile
# 危险 - 使用过时的基础镜像
FROM node:12-alpine      # EOL版本，大量已知CVE
FROM python:3.7-slim     # 不再接收安全更新
FROM ubuntu:18.04        # 已停止维护
```

### 4. 运行时组件版本暴露

```python
# 危险 - 泄露组件版本信息
@app.route('/api/status')
def status():
    return {
        "version": "1.0.0",
        "framework": f"Django {django.__version__}",
        "python": sys.version,
    }
```

### 5. 未修复的已知 N-day 漏洞链

常见高危组件漏洞链：
- Log4j (CVE-2021-44228 / CVE-2021-45046) — JNDI RCE
- Spring4Shell (CVE-2022-22965) — Spring Core RCE
- Apache Struts2 (S2-045 / S2-061) — OGNL RCE
- Fastjson (CVE-2022-25845) — AutoType RCE
- Nacos (CVE-2021-29441) — 认证绕过
- XXL-JOB (CVE-2022-36157) — 未授权访问

## 发现技术

1. 检查包管理器清单文件（package-lock.json, pom.xml, go.sum, requirements.txt, Gemfile.lock）
2. 运行 SBOM 生成工具（syft, trivy, dependency-check）
3. 对比已知漏洞数据库（OSV.dev, NVD, GitHub Advisory）
4. 检查 Docker/OCI 镜像的基础镜像版本和层
5. 检查运行时 /api/status, /actuator/info 等端点是否暴露版本信息

## 修复建议

```python
# 安全模式 - requirements.txt 锁定版本
requests==2.31.0
flask==3.0.0
cryptography==41.0.7
```

```json
// 安全模式 - package.json 使用 npm audit
{
  "scripts": {
    "postinstall": "npm audit || true",
    "snyk": "snyk test --all-projects"
  }
}
```

```dockerfile
# 安全模式 - 使用定期扫描更新基础镜像
FROM node:20-bookworm-slim  # 活跃维护版本
RUN apt-get update && apt-get upgrade -y
```

### 自动化方案

- CI/CD 中集成 `trivy filesystem .` 或 `npm audit`
- 使用 Dependabot / Renovate 自动创建依赖更新 PR
- 定期生成 SBOM（`cyclonedx-bom` / `syft`）
- 建立组件版本白名单策略
- 订阅 GitHub Advisory 和 OSV.dev 告警

## 严重性评估

- 已知 RCE 漏洞的组件：Critical
- 公开 PoC/利用链的已知漏洞：High
- 低危或需特殊条件的漏洞：Medium
- EOL 版本但无已知漏洞：Low
""",
)

__all__ = ["VULNERABLE_COMPONENTS"]
