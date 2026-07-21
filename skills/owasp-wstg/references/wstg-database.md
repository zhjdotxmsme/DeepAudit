# WSTG-DB: 数据库安全

## 检测清单

- [ ] 存储过程内含动态SQL拼接
- [ ] 触发器/视图含动态SQL执行
- [ ] ORM 框架使用原生查询拼接（HQL, JPQL, MyBatis ${}）
- [ ] 数据库用户权限过大（应用用户是 DBA）
- [ ] 数据库连接字符串含明文密码
- [ ] 数据库审计日志未开启
- [ ] 可提权到数据库超级用户
- [ ] 数据库备份文件可公开访问
- [ ] 过时数据库版本含已知 CVE
- [ ] 数据库端口对外开放（非必要暴露 0.0.0.0）
- [ ] 数据库链接未加密（非 TLS 连接）
- [ ] 盲注可用（时间延迟/布尔差异/OOB 通道可达）

## HQL/JPQL 注入

```java
// 危险 - HQL 拼接
Query q = session.createQuery("from User where name = '" + userName + "'");

// 安全
Query q = session.createQuery("from User where name = :name");
q.setParameter("name", userName);
```

## MyBatis ${} vs #{}

```xml
<!-- 危险 -->
<select id="getUser" resultType="User">
    SELECT * FROM users WHERE ${column} = #{value}
</select>

<!-- 安全 -->
<select id="getUser" resultType="User">
    SELECT * FROM users
    <where>
        <if test="column == 'name'">AND name = #{value}</if>
        <if test="column == 'email'">AND email = #{value}</if>
    </where>
</select>
```

## 数据库权限审计

```sql
-- 应用用户权限应遵循最小权限原则
-- MySQL
SHOW GRANTS FOR 'app_user'@'%';
-- 期望: GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.* TO 'app_user'
-- 不应有: GRANT ALL PRIVILEGES ON *.* TO 'app_user'  -- 超级权限

-- PostgreSQL
SELECT datname, rolname FROM pg_database d JOIN pg_roles r ON d.datdba = r.oid;
-- 检查应用用户是否拥有 CREATE/ALTER/DROP 权限
```

## 数据库审计日志

```sql
-- MySQL 开启审计
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
SET GLOBAL audit_log_policy = 'ALL';

-- PostgreSQL 审计配置 (pgAudit)
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'write,ddl,role'
```

## 盲注检测方法

```python
import requests, time

def test_blind_sqli(url, param):
    # 布尔盲注
    r1 = requests.get(url, params={param: "1 AND 1=1"})
    r2 = requests.get(url, params={param: "1 AND 1=2"})
    if r1.text != r2.text:
        print("布尔盲注可能")
    # 时间盲注
    start = time.time()
    r3 = requests.get(url, params={param: "1 AND SLEEP(5)"})
    if time.time() - start > 4.5:
        print("时间盲注可能 (MySQL)")
```

## OWASP 映射: A03:2021 Injection | A04:2021 Insecure Design | A06:2021 Vulnerable Components | A09:2021 Logging Failures
