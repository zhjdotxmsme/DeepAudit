---
name: java-vuln-scanner
description: Java 组件版本漏洞检测工具。扫描 pom.xml、build.gradle 或 jar 文件中的第三方依赖，匹配已知漏洞规则（CVE）并生成安全报告。适用于：(1) Java 项目依赖安全审计，(2) 识别 Log4j、Fastjson、Shiro、Spring 等高危组件漏洞，(3) jar 包反编译后的依赖分析。支持按目录层级分组输出，支持通过 java-decompile-mcp 反编译 .class/.jar 文件提取依赖信息。
---

# Java 组件漏洞扫描器

扫描 Java 项目依赖中的已知漏洞，支持 130+ 条 CVE 规则，按模块分组输出，并由 AI 生成漏洞触发点分析。

## 工作流程

### 1. 确定扫描目标

支持的输入类型：
- `pom.xml` - Maven 项目
- `build.gradle` - Gradle 项目
- `.jar` 文件 - 从文件名或 META-INF 提取依赖信息
- 目录 - 递归扫描上述所有文件，自动按模块分组

### 2. 处理 jar/class 文件（需要反编译时）

当目标是 `.jar` 或 `.class` 文件且无法直接提取依赖信息时，使用 `java-decompile-mcp` 工具反编译：

```
# 反编译单个文件
mcp__java-decompile-mcp__decompile_file(file_path="/path/to/file.jar")

# 反编译目录
mcp__java-decompile-mcp__decompile_directory(directory_path="/path/to/classes")
```

### 3. 执行漏洞扫描

运行扫描脚本，报告自动保存到 `{项目名}_audit/vuln_report/` 目录：

```bash
python3 scripts/scan_dependencies.py <目标路径> \
  --rules references/java-vulnerability.yaml \
  --no-deps
```

参数说明：
- `<目标路径>`: pom.xml、build.gradle、jar 文件或目录
- `--rules/-r`: 漏洞规则文件路径（使用内置规则）
- `--format/-f`: 输出格式 (markdown/json)
- `--output/-o`: 指定输出路径（不指定则自动生成）
- `--depth/-d`: 模块分组深度（默认: 2）
- `--no-deps`: 不显示依赖列表（简化输出）
- `--no-save`: 仅输出到终端，不保存文件

### 4. 分析扫描结果

报告按模块分组，每个模块按严重级别分类：
- 🔴 **Critical**: 立即修复（Log4Shell、Fastjson RCE、Shiro 反序列化等）
- 🟠 **High**: 尽快修复（Spring Boot Actuator、XStream 等）
- 🟡 **Medium**: 计划修复（JDBC 驱动漏洞、Guava 等）
- 🔵 **Low**: 建议升级（过时组件）

### 5. AI 漏洞触发点分析（重要）

扫描完成后，**必须**读取生成的报告文件，为检测到的漏洞生成触发点分析，并追加到报告末尾。

#### 分析步骤

1. 读取生成的报告文件（如 `xxx_audit/vuln_report/xxx_vuln_report_xxx.md`）
2. **识别项目运行环境**：
   - 检查项目使用的框架：Spring MVC / Spring Boot / Struts2 / Servlet / JAX-RS 等
   - 检查容器类型：Tomcat / Jetty / Undertow / WebLogic / WildFly 等
   - 查找配置文件：`web.xml`、`struts.xml`、`application.yml`、`applicationContext.xml` 等
3. **分析路由和入口点**：
   - 扫描 Controller / Action / Servlet 类，提取 HTTP 路由映射
   - 识别文件上传、JSON/XML 解析、用户输入处理等关键入口
   - 结合 java-route-mapper 技能（如已加载）获取完整路由信息
4. 提取检测到的**唯一漏洞组件**列表（去重）
5. 为每个高危组件生成以下分析内容：
   - **常见触发点**：该漏洞在代码中的触发位置
   - **危险代码模式**：容易触发漏洞的代码写法（结合当前框架环境）
   - **攻击向量**：攻击者如何利用此漏洞
   - **受影响的路由/接口**：根据路由分析，列出可能受影响的具体接口
   - **检测建议**：如何在代码中搜索潜在的漏洞触发点
6. 追加分析内容到报告：
   - 使用 Read 工具读取完整报告内容
   - 将分析内容拼接到末尾
   - 使用 Write 工具写入完整内容（避免 Edit 匹配失败）

#### 环境识别方法

根据以下特征识别项目环境（参考 java-route-mapper 技能的识别策略）：

**Web 框架识别：**

| 框架 | 识别特征 | 配置文件 | 关键依赖 |
|------|---------|---------|---------|
| Spring MVC | `@Controller`、`@RequestMapping`、`@RestController` | `dispatcher-servlet.xml`、`spring-mvc.xml` | `spring-webmvc.jar` |
| Spring Boot | `@SpringBootApplication`、Spring Boot starter | `application.properties`、`application.yml` | `spring-boot-starter-*.jar` |
| Struts 2 | `ActionSupport`、`\<action\>` 配置 | `struts.xml`、`struts-plugin.xml` | `struts2-core.jar` |
| Servlet | `HttpServlet`、`@WebServlet`、`\<servlet\>` 配置 | `web.xml` | `javax.servlet-api.jar` |
| JAX-RS | `@Path`、`@GET`、`@POST`、`@PathParam` | `web.xml`（REST servlet 映射） | `jersey-*.jar`、`cxf-rt-*.jar` |
| CXF Web Services | `@WebService`、`\<jaxws:endpoint\>` | `applicationContext.xml`、`cxf-servlet.xml` | `cxf-*.jar` |

**容器识别：**

| 容器 | 识别特征 | 配置文件 |
|------|---------|---------|
| Tomcat | `catalina.jar`、`org.apache.catalina` | `server.xml`、`context.xml` |
| Jetty | `jetty-*.jar`、`org.eclipse.jetty` | `jetty.xml`、`webdefault.xml` |
| Undertow | `undertow-*.jar`、`io.undertow` | `undertow-handlers.conf` |
| WebLogic | `weblogic.jar`、`weblogic.xml` | `weblogic.xml`、`weblogic-application.xml` |
| WildFly/JBoss | `jboss-*.jar`、`org.jboss` | `jboss-web.xml`、`standalone.xml` |

**框架组合识别：**

多框架混合项目需要分别识别并分析：
- Struts2 + Spring：检查 `struts-spring-plugin.jar` 和 Spring 配置
- Spring MVC + CXF：检查 `\<jaxws:endpoint\>` 和 `@Controller` 共存
- Servlet + Filter 链：分析 `web.xml` 中的 filter-mapping 顺序

#### 追加内容格式

追加到报告末尾的内容应包含以下结构：

**标题：** `## 🔍 漏洞触发点分析（AI 生成）`

**环境信息：** `### 🌐 项目环境` - 列出识别到的框架和容器

**每个组件的分析包含：**

1. **组件标题** - 如：`### Struts2 (struts2-core 2.5.17)`

2. **常见触发点** - 列出该漏洞在代码中的触发位置

3. **危险代码模式** - 展示容易触发漏洞的代码写法（使用 java 代码块）

4. **攻击向量** - 说明攻击者如何利用此漏洞

5. **受影响的路由** - 根据环境分析，列出可能受影响的接口路径

6. **代码搜索建议** - 提供 grep 命令帮助定位风险代码（使用 bash 代码块）

#### 示例：Bouncy Castle 分析

    ### Bouncy Castle (bcprov-jdk15on 1.53)

    **常见触发点：**
    - LDAP 证书验证处理
    - X.509 证书 DN 解析
    - CertStore 操作

    **危险代码模式：**

        // 用户输入直接用于证书查询
        X509CertSelector selector = new X509CertSelector();
        selector.setSubject(userInput);  // 危险：用户输入未过滤
        CertStore store = CertStore.getInstance("LDAP", params);

    **攻击向量：**
    - CVE-2024-30171: 通过证书 DN 中的特殊字符进行 LDAP 注入

    **代码搜索建议：**

        grep -r "LdapCertStore\|CertStore.*LDAP" --include="*.java"
        grep -r "X509CertSelector" --include="*.java"

## 漏洞规则覆盖

规则文件 `references/java-vulnerability.yaml` 包含 130+ 条规则，覆盖：

| 组件类别 | 主要漏洞 |
|---------|---------|
| Log4j | CVE-2021-44228 (Log4Shell), CVE-2021-45046 |
| Fastjson | CVE-2022-25845, CVE-2017-18349 |
| Spring | CVE-2022-22965 (Spring4Shell), CVE-2022-22963 |
| Struts2 | S2-045, S2-046, S2-057, S2-061 |
| Shiro | CVE-2016-4437, CVE-2020-11989, CVE-2020-17510 |
| Jackson | CVE-2020-36518, CVE-2019-12384 |
| XStream | CVE-2021-39144 等 15 个 CVE |
| ActiveMQ | CVE-2023-46604 |
| JDBC 驱动 | MySQL, PostgreSQL, H2, Derby 等 |

## 示例

### 完整扫描流程

```bash
# 1. 执行扫描
python3 scripts/scan_dependencies.py /path/to/webapp \
  --rules references/java-vulnerability.yaml \
  --no-deps

# 2. 输出示例:
# [INFO] 创建输出目录: webapp_audit/vuln_report
# [INFO] 报告已保存到: webapp_audit/vuln_report/webapp_vuln_report_20260204_101747.md
# 📊 扫描摘要:
#    模块数量: 4
#    依赖总数: 262
#    漏洞总数: 80
#    🔴 严重: 24

# 3. AI 自动读取报告并追加触发点分析
```

### 输出报告结构

```
webapp_audit/vuln_report/
└── webapp_vuln_report_20260204_101747.md
    ├── 扫描概览
    ├── 模块风险摘要
    ├── 漏洞详情（按模块分组）
    └── 🔍 漏洞触发点分析（AI 生成）  <-- 自动追加
```
