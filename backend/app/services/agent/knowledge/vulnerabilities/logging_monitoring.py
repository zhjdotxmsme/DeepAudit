"""
安全日志和监控失效 (A09:2021) 漏洞知识

OWASP Top 10 A09:2021 — Security Logging and Monitoring Failures
"""

from ..base import KnowledgeDocument, KnowledgeCategory


LOGGING_MONITORING_FAILURE = KnowledgeDocument(
    id="vuln_logging_monitoring",
    title="安全日志和监控失效",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["logging", "monitoring", "audit", "detection", "forensics", "siem"],
    severity="medium",
    cwe_ids=["CWE-778", "CWE-223", "CWE-532"],
    owasp_ids=["A09:2021"],
    content="""
# 安全日志和监控失效

## 概述

安全日志和监控失效使攻击者能够在缺乏检测的情况下进行攻击活动。
没有足够的日志记录和监控，安全事件可能长时间不被发现，
报警响应不及时会导致数据泄露范围扩大。

## 漏洞模式

### 1. 未记录安全关键事件

```python
# 危险模式 - 认证失败不记录
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form)
    if not user:
        return {"error": "认证失败"}  # 未记录失败尝试
    return {"token": create_token(user)}
```

```python
# 危险模式 - 权限提升不记录
def update_user_role(target_user):
    target_user.role = request.form['role']
    db.commit()
    # ⚠️ 未记录谁修改了角色、从什么修改为什么
```

### 2. 日志注入/污染

```python
# 危险模式 - 未过滤的日志输入
import logging
logger = logging.getLogger(__name__)

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    logger.info(f"搜索: {query}")  # 可被注入换行/伪造日志
```

攻击者输入 `正常查询\\n[INFO] 管理员登录成功` 可污染日志分析。

### 3. 敏感信息写入日志

```python
# 危险模式 - 记录敏感信息
logger.info(f"用户登录: {username}, Token: {token}")
logger.debug(f"SQL: {query}, 参数: {params}")  # 参数可能含密码
logger.error(f"支付失败: 信用卡 {card_number}")
```

### 4. 缺乏实时告警

```python
# 危险模式 - 仅记录不告警
def detect_brute_force(username):
    failures = redis.get(f"fail:{username}")
    if failures and int(failures) > 10:
        logger.warning(f"爆破检测: {username}")
        # ⚠️ 仅记录，未触发告警/阻断
```

### 5. 日志存储不安全

```python
# 危险模式 - 日志可被攻击者删除或篡改
LOG_FILE = "/app/logs/app.log"  # 与应用同权限，可被删除
```

### 6. 监控盲区窗口

```python
# 危险模式 - 无持续监控
# 只在业务高峰期后手动检查日志
# 凌晨2-6点攻击窗口无告警覆盖
# 无跨系统关联分析（Web日志≠数据库审计日志≠操作系统日志）
```

## 发现技术

1. 检查认证/授权模块是否有 audit log
2. 搜索 logger 调用中是否存在敏感数据（密码、Token、信用卡）
3. 验证日志是否包含关键字段：时间戳、用户ID、源IP、操作类型、结果
4. 检查日志存储：权限、备份、不可篡改性
5. 检查是否有 SIEM/告警规则覆盖关键事件
6. 确认敏感操作（角色变更、转账、数据导出）是否记录日志

## 修复建议

```python
import logging
from datetime import datetime

# 安全模式 - 结构化审计日志
class AuditLogger:
    def __init__(self):
        self.logger = logging.getLogger("audit")
    
    def log_security_event(self, event_type, user_id, detail, result):
        self.logger.info(json.dumps({
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            "user_id": user_id,
            "source_ip": get_client_ip(),
            "detail": detail,
            "result": result,
            # ⚠️ 不记录密码、Token、PII
        }))

# 使用
audit = AuditLogger()
audit.log_security_event(
    event_type="login_failure",
    user_id=username,
    detail=f"第{attempts}次认证失败",
    result="denied"
)
```

### 日志安全原则

```python
# 1. 日志输入过滤（防注入）
def safe_log(msg: str):
    sanitized = msg.replace('\\n', '_').replace('\\r', '_')
    logger.info(sanitized)

# 2. 敏感数据脱敏
def mask_sensitive(value: str) -> str:
    if len(value) > 4:
        return value[:4] + "****"
    return "****"

# 3. 日志独立存储（只追加、防篡改）
# 日志输出至独立卷/独立的日志服务
```

### 告警规则示例

| 事件 | 阈值 | 响应 |
|------|------|------|
| 登录失败 | 5次/分钟/用户 | 临时锁定 + 告警 |
| API 403 | 50次/分钟/IP | WAF 临时阻断 |
| 角色变更 | 任何变更 | 即时通知安全团队 |
| 批量数据导出 | >1000条/分钟 | 审批确认 |
| 异常时间访问 | 凌晨0-6点管理操作 | 二次认证 + 记录 |

## 严重性评估

- 无任何安全审计日志：High
- 记录但不告警：Medium
- 有日志但含敏感数据泄漏：Medium
- 日志可被篡改/删除：High
- 仅部分操作记录：Low
""",
)

__all__ = ["LOGGING_MONITORING_FAILURE"]
