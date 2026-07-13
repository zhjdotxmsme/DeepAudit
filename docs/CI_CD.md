# DeepAudit CI/CD 集成指南

在 CI/CD 流水线中运行 DeepAudit，实现每次 Pull Request 自动代码安全审计，findings 直接呈现到 GitHub / GitLab / SonarQube 的安全面板。

本指南覆盖：

- 使用 `deepaudit` CLI 触发远程扫描
- 在 GitHub Actions 中启用（含 Diff-Scope 增量扫描）
- SARIF 报告与严重级别 Gate
- GitLab CI / Jenkins / 其他 Runner 的通用模板

---

## 1. 前置条件

- 一台可访问的 DeepAudit 后端服务（自建或 SaaS），URL 记为 `DEEPAUDIT_URL`
- 通过管理后台创建一个 API Token，记为 `DEEPAUDIT_TOKEN`
- 在 DeepAudit 中创建目标项目，取项目 ID `DEEPAUDIT_PROJECT_ID`

---

## 2. DeepAudit CLI

CLI 与后端解耦：CI Runner 只需要 Python 3.10+，不依赖 Docker、不依赖数据库。

### 2.1 安装

```bash
pip install deepaudit-backend
deepaudit --help
```

或从源码安装：

```bash
pip install -e ./backend
```

### 2.2 快速使用

```bash
deepaudit scan \
  --url https://deepaudit.example.com \
  --token "$DEEPAUDIT_TOKEN" \
  --project-id "$DEEPAUDIT_PROJECT_ID" \
  --path . \
  --wait \
  --sarif-out deepaudit.sarif \
  --fail-on high
```

CLI 会：

1. 把 `--path` 目录打包（默认排除 `.git / node_modules / __pycache__ / .venv / dist / build / target / vendor` 等）
2. 上传到后端 `POST /api/v1/scan/upload-zip`
3. 轮询任务状态直到 `completed`
4. 拉取 SARIF 2.1.0 报告（`GET /api/v1/tasks/{id}/report/sarif?dedupe=true`）
5. 根据 `--fail-on` 决定退出码

### 2.3 命令行参数

| 参数 | 环境变量 | 说明 |
| --- | --- | --- |
| `--url` | `DEEPAUDIT_URL` | DeepAudit 后端 URL |
| `--token` | `DEEPAUDIT_TOKEN` | Bearer Token |
| `--email` / `--password` | `DEEPAUDIT_EMAIL` / `DEEPAUDIT_PASSWORD` | 无 Token 时用邮箱密码登录 |
| `--project-id` | `DEEPAUDIT_PROJECT_ID` | 目标项目 ID |
| `--path` | | 待扫描目录，默认 `.` |
| `--exclude` | | 追加排除的目录名（可重复） |
| `--rule-set-id` | `DEEPAUDIT_RULE_SET_ID` | 指定审计规则集 |
| `--prompt-template-id` | `DEEPAUDIT_PROMPT_TEMPLATE_ID` | 指定提示词模板 |
| `--diff-files` | | 只扫描这些文件（可重复，用于 PR 增量扫描） |
| `--wait / --no-wait` | | 是否等待任务完成，默认 `--wait` |
| `--timeout` | | 等待超时秒数，默认 1800 |
| `--sarif-out` | | SARIF 输出路径 |
| `--dedupe / --no-dedupe` | | 是否按指纹去重，默认开启 |
| `--fail-on` | | 严重级别 Gate（`critical / high / medium / low / info`），默认 `high` |

### 2.4 退出码约定

| 退出码 | 含义 |
| --- | --- |
| `0` | 扫描完成，未发现达到 `--fail-on` 阈值的漏洞 |
| `1` | 扫描完成，存在达到阈值的漏洞（CI 应失败） |
| `2` | 配置错误 / 网络错误 / 服务端错误 |

`1` 与 `2` 的分离让 CI 可以区分"审计发现问题"和"审计流程出错"。

---

## 3. GitHub Actions

仓库已提供开箱即用模板 `.github/workflows/deepaudit.yml`。使用步骤：

1. 复制该文件到你的仓库 `.github/workflows/deepaudit.yml`
2. 在仓库 Settings → Secrets and variables → Actions 添加：
    - `DEEPAUDIT_URL`
    - `DEEPAUDIT_TOKEN`
    - `DEEPAUDIT_PROJECT_ID`
3. 打开 Pull Request，Action 会自动运行并把 SARIF 报告推送到 **Security → Code scanning alerts**。

关键机制：

- PR 事件下 workflow 会 `git diff --name-only` 得到变更文件列表，只扫描这些文件（Diff-Scope 增量扫描），大幅缩短 PR 反馈时长。
- SARIF 通过 `github/codeql-action/upload-sarif@v3` 上传，findings 会直接标注到 PR 变更行。
- 即使 `deepaudit scan` 因超阈值退出 `1`，SARIF 仍会被上传（`if: always()`）。

### 3.1 只在 PR 上跑，主干不跑

```yaml
on:
  pull_request:
    branches: [main, develop]
```

删除 `push:` 分支即可。

### 3.2 提高严重级别 Gate

例如只在存在 `critical` 时才失败：

```yaml
- run: |
    deepaudit scan ... --fail-on critical
```

### 3.3 全量扫描而非增量

去掉 workflow 里的 `Compute changed files (PR)` 和 `Build --diff-files args` 两个 step，`deepaudit scan` 会默认扫描 `--path` 下所有文件。

---

## 4. GitLab CI

```yaml
deepaudit:
  stage: test
  image: python:3.11-slim
  variables:
    DEEPAUDIT_URL: "$DEEPAUDIT_URL"
    DEEPAUDIT_TOKEN: "$DEEPAUDIT_TOKEN"
    DEEPAUDIT_PROJECT_ID: "$DEEPAUDIT_PROJECT_ID"
  before_script:
    - pip install deepaudit-backend
  script:
    - deepaudit scan --path . --wait --sarif-out deepaudit.sarif --fail-on high
  artifacts:
    when: always
    paths:
      - deepaudit.sarif
    reports:
      # GitLab Ultimate 支持 SAST report ingestion
      sast: deepaudit.sarif
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

---

## 5. Jenkins Pipeline

```groovy
pipeline {
  agent { docker { image 'python:3.11-slim' } }

  environment {
    DEEPAUDIT_URL         = credentials('deepaudit-url')
    DEEPAUDIT_TOKEN       = credentials('deepaudit-token')
    DEEPAUDIT_PROJECT_ID  = credentials('deepaudit-project-id')
  }

  stages {
    stage('Install CLI') {
      steps { sh 'pip install deepaudit-backend' }
    }
    stage('Scan') {
      steps {
        sh '''
          deepaudit scan \
            --path . \
            --wait \
            --sarif-out deepaudit.sarif \
            --fail-on high
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'deepaudit.sarif', allowEmptyArchive: true
    }
  }
}
```

---

## 6. SARIF 报告结构

DeepAudit 输出符合 **SARIF 2.1.0** 规范的 JSON，可被以下平台原生消费：

- GitHub Code Scanning
- GitLab SAST (Ultimate)
- SonarQube 10.3+
- Azure DevOps Advanced Security
- Semgrep AppSec Platform

每个 `result` 包含：

- `ruleId` — DeepAudit 内置规则 ID 或 CVE 编号
- `level` — `error / warning / note`
- `properties.security-severity` — 原始严重级别（`critical / high / medium / low / info`）
- `properties.fingerprint` — 指纹（用于 dedupe，跨扫描保持稳定）
- `locations[].physicalLocation` — 文件 + 行号
- `taxa` — CWE / OWASP 分类

Dedupe 策略：按 `(rule_id, file_path, code_hash, sink_pattern)` 指纹合并，去重比例通常 15–30%。

---

## 7. 常见问题

**Q1：CI 环境没有装 Docker 也能跑吗？**
可以。CLI 只是 HTTP 客户端，`pip install` 就够了。

**Q2：内网 DeepAudit 服务器 CI 上不去？**
自建 Runner + 私有网络，或用反向代理暴露到 CI 白名单。

**Q3：扫描时间太久？**
- PR 场景启用 `--diff-files` 增量扫描
- 后台侧调整 `scan_config.exclude_patterns`
- 用 `--fail-on critical` 只挡最严重的问题

**Q4：如何跳过某些误报？**
在 DeepAudit 后台把对应 finding 标记为 "确认误报"，指纹会加入忽略列表，之后所有扫描自动过滤。

---

## 8. 相关文档

- [ARCHITECTURE.md](./ARCHITECTURE.md) — 整体架构
- [AGENT_AUDIT.md](./AGENT_AUDIT.md) — Multi-Agent 审计流程
- [CONFIGURATION.md](./CONFIGURATION.md) — 服务端配置
