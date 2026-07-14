# Dubbo Hessian2 反序列化

## 攻击面

Apache Dubbo 默认协议 `dubbo`（在 Netty 上跑），编解码器默认 Hessian2。任何提供者
（Provider）在网络可达的情况下，攻击者可构造 Hessian2 payload 触发反序列化。

## CVE 汇总

| CVE | 版本 | 触发 |
|-----|------|------|
| CVE-2021-25641 | ≤ 2.7.10 | 编解码器可选 Kryo/FST/JavaSerialize，攻击者切换 |
| CVE-2021-30179 | ≤ 2.7.9 | Generic invocation URL 反序列化 |
| CVE-2021-32824 | ≤ 2.7.10 | HTTP invoker 相关反序列化 |
| CVE-2022-39198 | ≤ 3.0.11 | Metadata Service |
| CVE-2023-23638 | ≤ 3.1.5 | 未修完 pre-check bypass |

## CVE-2021-25641 举例

Dubbo 请求头允许指定序列化方式：

```
+---------+----------+----------+------------+
| Magic   | Flag     | ID       | Body Len   |
+---------+----------+----------+------------+
| 0xda 0xbb | 0xda ... 序列化 ID  |
```

Flag 字节的低 5 位是序列化 ID：
- 2 = Hessian2
- 3 = Java 原生
- 4 = Fastjson
- 8 = Kryo
- 16 = FST

服务端根据 Flag 选序列化器；攻击者切到 Java 原生（Serialization ID=3）或 Kryo → 触发
gadget 链。

## Payload 构造

依赖 ysoserial + Dubbo 私有协议：

```java
byte[] gadget = ysoserial.payloads.CommonsCollections6.getBytes(cmd);
// 包装到 Dubbo 请求：
byte[] request = new byte[16 + gadget.length];
request[0] = (byte)0xda; request[1] = (byte)0xbb;
request[2] = (byte)(0x80 | 3);  // Flag: request + Java Serialize
// ... requestId(8B) + bodyLen(4B) + gadget
socket.write(request);
```

## 修复

### 版本升级

- Dubbo 2.7.15+
- Dubbo 3.1.6+ / 3.2.0+

### 强制安全序列化

```yaml
dubbo:
  application:
    serialize-check-status: STRICT   # 3.x 严格模式
    serialize-check-blocked-list-enable: true
  protocol:
    serialization: hessian2   # 只允许 hessian2，不允许切换
```

### 类白名单

Dubbo 3.x 支持 `AllowClassNotifyListener` 白名单：

```java
public class SecurityConfig {
    @Bean
    public AllowClassNotifyListener allowList() {
        return () -> Set.of(
            "com.myapp.dto.*",
            "com.myapp.request.*"
        );
    }
}
```

### 网络隔离

Provider 端口只对内网 Consumer 开放，禁止公网直连。Consul/Nacos 注册中心也应鉴权。

## 检测

```bash
# 扫描内网 Dubbo 端口
nmap -p 20880,20881,20882 --script=dubbo-info 10.0.0.0/24
```

Provider 存在但无鉴权 = 高危。

## 审计动作

- [ ] Dubbo 版本
- [ ] `serialization=hessian2` 且不允许运行时切换
- [ ] `serialize-check-status=STRICT` (3.x)
- [ ] 反序列化白名单是否配置
- [ ] Provider 端口暴露面（内网 vs 公网）
- [ ] Consumer 是否走 mTLS

## 相关规则

- CWE: CWE-502 (Deserialization of Untrusted Data)
- 内建 pattern: `dubbo_deser`
- CVSS: 9.8
