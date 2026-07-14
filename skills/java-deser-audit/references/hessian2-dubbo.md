# Hessian2 反序列化通用攻击面

## 触发场景

Hessian2 广泛应用于：
- Dubbo 默认协议
- Spring Remoting HessianServiceExporter
- Burlap（较少见）
- 自研 RPC 使用 Hessian2 编解码

任意接受 `Content-Type: x-application/hessian` 或私有二进制协议的端点，若允许
任意类 → RCE。

## Gadget 链

不同于 Java 原生反序列化，Hessian2 有独立的 gadget 链：

- **Rome (RomeTypeMarshalDecoderTemplatesImpl)** — 最经典
- **XBean (XBean-Reflect)** — 通过 XBeanReflectPropertySources
- **Spring PartiallyComparableAdvisorHolder** — Spring AOP
- **Resin (com.caucho.naming.QName)** — Resin 环境
- **CommonsBeanutils-JDK7 + Hessian2**（部分变种）

工具：Marshalsec、ysoserial （部分链）。

## Spring HessianServiceExporter

```java
@Bean(name = "/userService")
public HessianServiceExporter userService(UserService userService) {
    HessianServiceExporter e = new HessianServiceExporter();
    e.setService(userService);
    e.setServiceInterface(UserService.class);
    return e;
}
```

发布后 URL 是 `/userService`，任何 POST + Hessian2 payload 即触发反序列化。
即使 payload 声称调用某个方法，反序列化在方法调用之前 = 无需知道接口签名即可 RCE。

## 修复

### 1. 换协议

Spring 4.2+ 优先用 `HttpInvokerServiceExporter`（更严）或转向 REST。
新项目**不要**用 Hessian2。

### 2. Dubbo 层白名单

```yaml
dubbo:
  application:
    serialize-check-status: STRICT
  provider:
    serialization: hessian2
```

3.x 严格模式 + `AllowClassNotifyListener` 白名单（见 xxljob-hessian-deser.md）。

### 3. 自定义 SerializerFactory

```java
public class SafeSerializerFactory extends SerializerFactory {
    private static final Set<String> BLOCKED = Set.of(
        "com.sun.rowset.JdbcRowSetImpl",
        "org.apache.commons.beanutils.BeanComparator",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "com.rometools.rome.feed.impl.ObjectBean",
        "org.springframework.aop.aspectj.AspectJPointcutAdvisor",
        // ...
    );

    @Override
    public Deserializer getDeserializer(Class cl) throws HessianProtocolException {
        if (BLOCKED.contains(cl.getName())) {
            throw new HessianProtocolException("Blocked: " + cl.getName());
        }
        return super.getDeserializer(cl);
    }
}
```

### 4. 网络隔离

RPC 端口仅内网可达，不映射到公网。

## 检测

Wireshark / tcpdump：

```
tcp port 20880
```

payload 首字节：
- Hessian2: `H`  (0x48)
- Hessian2 method call: `c` (0x63) then version bytes
- Java 原生序列化: `\xac\xed\x00\x05`

出现 Hessian2 流量但流向公网 = 高风险。

## 审计动作

```bash
grep -rn 'HessianServiceExporter\|HessianProxyFactory\|Hessian2Input\|Hessian2Output' src/main/java/
```

对每个匹配：
- 服务端是否公网可达
- 是否走 mTLS / 网络白名单
- 依赖版本（hessian ≥ 4.0.65，且需二次白名单）

## 相关规则

- CWE: CWE-502
- 内建 pattern: `dubbo_deser`
- CVSS: 9.8
- 参考：https://github.com/mbechler/marshalsec/blob/master/marshalsec.pdf
