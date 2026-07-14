# MyBatis `<sql>` 片段与 `<include>` 传参注入

## 攻击场景

`<sql>` 定义可复用的 SQL 片段，`<include>` 引入并支持 `<property>` 传参。
若片段内使用 `${}` 引用属性名，且属性值最终来自用户输入，即注入。

```xml
<!-- ❌ 危险：片段内 ${where} 由外层传入 -->
<sql id="commonWhere">
    <where>
        ${where}
    </where>
</sql>

<select id="list" resultType="User">
    SELECT * FROM users
    <include refid="commonWhere">
        <property name="where" value="name='${userName}'"/>
    </include>
</select>
```

`userName` 来自 HTTP 参数时，攻击者可注入 `x' OR 1=1--`。

## 隐蔽变形

### 变形 1：`<bind>` 拼接后当 `${}` 用

```xml
<bind name="likeName" value="'%' + name + '%'"/>
<select id="search">
    SELECT * FROM t WHERE name LIKE '${likeName}'
</select>
```

`<bind>` 内部走 OGNL，`+` 拼接后被 `${likeName}` 文本替换。

### 变形 2：`<foreach>` 中的 `${item}`

```xml
<!-- ❌ 危险 -->
<foreach collection="ids" item="id" separator=",">
    ${id}
</foreach>
```

### 变形 3：多级 `<include>` 链

`Mapper A` 引用片段 `X`，`X` 又引用片段 `Y`，属性沿调用链传递，
在最末端片段中被 `${}` 使用。审计时容易只看直接调用点。

## 安全写法

```xml
<!-- ✅ 安全：片段内只用 #{} 与结构化标签 -->
<sql id="commonWhere">
    <where>
        <if test="name != null">AND name = #{name}</if>
        <if test="status != null">AND status = #{status}</if>
    </where>
</sql>

<select id="list" resultType="User">
    SELECT * FROM users
    <include refid="commonWhere"/>
</select>
```

## 审计动作

```bash
# 全项目查 ${} 在 mapper xml
grep -rn '\${' src/main/resources/mapper/

# 查 <property name= ... value= 传入拼接
grep -rn '<property.*value=".*\${' src/
```

## 相关规则

- CWE: CWE-89
- 内建 pattern: `mybatis_dollar_injection`
