# 第 1 章　RASP 概述

## 1.1 定义

**RASP（Runtime Application Self-Protection，运行时应用自我保护）**这个概念由 Gartner 在 2014 年前后提出，指一种**内建于或链接到应用运行时环境中**的安全技术。它利用运行时插桩（instrumentation），从应用内部获取执行信息，**实时检测并阻断攻击**。

核心要点：

- **运行位置**：在应用进程内部（JVM、CPython 解释器、Node.js 进程、PHP 扩展等），不在网络边界。
- **工作方式**：在敏感函数（Sink）上插入检查代码。函数被调用时，结合“当前请求的用户输入”和“函数参数、调用栈”判断是否构成攻击。
- **两种模式**：
  - **监控模式（Monitor / 观察模式）**：只记录、上报，不阻断。
  - **防护模式（Protect / 阻断模式）**：检测到攻击时抛出异常或返回拦截页面，中止这次危险操作。

## 1.2 工作原理示意

```
             HTTP 请求  ?id=1' or '1'='1
                  │
    ┌─────────────▼──────────────────────────────────────┐
    │  应用进程（JVM）                                      │
    │                                                      │
    │  [Hook] Servlet/Filter 入口 ──► 记录请求上下文          │
    │        (URL/参数/Header/Body 存入 ThreadLocal)        │
    │                  │                                   │
    │            业务代码 Controller → Service → DAO        │
    │                  │                                   │
    │  [Hook] Statement.executeQuery(sql) ◄── 插桩点         │
    │        │                                             │
    │        ├─► 检测引擎：sql = "select * from t where     │
    │        │     id=1' or '1'='1'"                       │
    │        │     用户输入 "1' or '1'='1" 改变了 SQL 语法结构 │
    │        │     ⇒ 判定为 SQL 注入                         │
    │        │                                             │
    │        └─► 阻断：抛出 SecurityException / 返回拦截页     │
    │            上报：告警（含请求、调用栈、SQL）发往管理平台    │
    └──────────────────────────────────────────────────────┘
```

**关键思想**：WAF 看到的是“字符串像不像攻击”，RASP 看到的是“这个字符串最终到了哪个危险函数、有没有真的改变程序的语义”。

## 1.3 与其他安全产品的对比

| 维度 | WAF | RASP | IAST | SAST | DAST |
|---|---|---|---|---|---|
| 部署位置 | 网络边界/反向代理 | 应用进程内 | 应用进程内（测试环境） | 源代码 | 外部扫描 |
| 运行阶段 | 生产 | **生产** | 测试 | 开发 | 测试 |
| 是否阻断 | 是 | **是** | 否（只发现漏洞） | 否 | 否 |
| 检测依据 | 流量特征/正则 | 执行上下文 + 语义 | 污点跟踪 | 代码数据流 | 响应特征 |
| 误报 | 较高 | **低** | 低 | 高 | 中 |
| 绕过难度 | 编码/分块/加密可绕过 | 难（看最终执行参数） | — | — | — |
| 0day 防护 | 弱（依赖规则） | **较强（基于行为）** | — | — | — |
| 性能影响 | 无（独立部署） | 有（1%～10%） | 较大 | 无 | 无 |
| 接入成本 | 低 | 中（需要重启或 attach） | 中 | 低 | 低 |

**RASP 与 IAST 的关系**：二者都用插桩，技术栈高度重合。IAST 在测试环境做污点追踪，用来**找漏洞**；RASP 在生产环境用来**挡攻击**。很多厂商用同一个 Agent 同时提供两种能力。本平台在架构上预留了 IAST 扩展点（见第 3 章）。

**RASP 与 WAF 是互补关系**：WAF 挡住大量扫描和 CC 流量，RASP 处理绕过 WAF 的精准攻击和 0day，并给出代码级的告警证据（调用栈）。

## 1.4 RASP 能防什么

| 攻击类型 | 典型 Hook 点（Java） | 说明 |
|---|---|---|
| SQL 注入 | JDBC `Statement/PreparedStatement.execute*` | 判断用户输入是否改变 SQL 语法结构 |
| 命令执行 | `java.lang.ProcessImpl`/`UNIXProcess` 的 `forkAndExec` | 判断命令中是否含用户输入，或调用栈是否异常 |
| 任意文件读/写/删/遍历 | `FileInputStream`、`FileOutputStream`、`File.delete/list`、NIO `Files` | 判断路径穿越、敏感文件、写 Webshell |
| SSRF | `URL.openConnection`、`HttpClient`、`OkHttp`、`Socket.connect` | 判断目标是否内网 IP、云元数据地址 |
| 反序列化 | `ObjectInputStream.resolveClass`、Fastjson/Jackson/XStream | 类名黑白名单、Gadget 识别 |
| JNDI 注入（Log4Shell 等） | `InitialContext.lookup` | 拦截来自用户输入的 ldap/rmi lookup |
| 表达式注入 | OGNL、SpEL、MVEL、EL、Groovy | 表达式内容检测 |
| XXE | XML 解析器实体解析 | 禁止外部实体/敏感协议 |
| 文件上传 Webshell | multipart 解析 + 写文件 | 可执行脚本后缀写入 Web 目录 |
| 内存马 | 动态注册 Filter/Servlet/Listener/Controller、`defineClass` | 运行时新增组件且无对应 class 文件 |
| 敏感信息泄露 | 响应输出 | 身份证、手机号、堆栈信息外泄（可选） |
| 基线检查 | 启动时 | 弱口令、默认配置、危险依赖版本（CVE） |

## 1.5 RASP 的优势与局限

**优势**

1. 误报率低：基于真实执行上下文，而不是猜流量。
2. 不怕编码和加密：HTTPS、多层 URL 编码、分块传输都已经被应用自己解码过了。
3. 能防 0day：例如不管哪个组件的反序列化漏洞，最终都要执行命令或加载恶意类，RASP 在行为层面都能拦下。
4. 告警可读性好：附带调用栈，开发能直接定位漏洞代码。
5. 跟随应用迁移：容器、云上、内网应用都能防护，不依赖网络拓扑。

**局限 / 挑战**

1. **语言相关**：每种语言都要单独开发 Agent，成本高。
2. **性能开销**：Hook 点越多、检测越复杂，开销越大，需要严格控制。
3. **稳定性风险**：Agent 和业务在同一个进程里，Agent 的 bug 可能拖垮业务。这是最大的工程挑战。
4. **兼容性**：JDK 版本（6～21+）、中间件（Tomcat/Jetty/Undertow/WebLogic/WebSphere/东方通/宝兰德等）、框架种类繁多。
5. **无法防护逻辑漏洞**：越权、业务逻辑缺陷超出 RASP 的能力范围。
6. **组织阻力**：业务方担心性能和稳定性，推广时需要灰度机制和熔断机制作为保障。

## 1.6 业界方案

| 方案 | 类型 | 语言支持 | 特点 |
|---|---|---|---|
| **OpenRASP**（百度） | 开源 | Java、PHP | 检测逻辑写在 JS 插件中，用 V8/Rhino 执行，可热更新；有完整管理后台；近年维护不活跃。**架构最值得参考** |
| **jrasp**（jvm-rasp） | 开源/部分闭源 | Java | 基于 jvm-sandbox 思想，支持 attach 热插拔、类加载器隔离；许可证需核实 |
| **jvm-sandbox**（阿里） | 开源 | Java | 不是 RASP，是通用的 AOP 无侵入框架，其模块隔离、热插拔设计可借鉴 |
| **Elkeid RASP**（字节） | 开源 | Java、Python、Go、Node.js、PHP | 多语言探针 + 统一 Manager 注入，适合主机安全场景 |
| Contrast Protect | 商业 | 多语言 | IAST + RASP 一体 |
| Imperva RASP | 商业 | Java、.NET | — |
| Datadog ASM / Dynatrace AppSec | 商业 | 多语言 | APM 厂商附带的 RASP 能力 |
| 国内厂商（悬镜、默安、安百、靖云甲等） | 商业 | 以 Java 为主 | 本土中间件适配好 |

## 1.7 本平台的定位

- **第一阶段**：做一个可以在生产环境稳定运行的 **Java RASP**，覆盖 OWASP Top 10 中能在运行时检测的主要漏洞类型，并支持内存马检测。配套一个能管理数千实例的管理平台。
- **第二阶段**：扩展组件漏洞（SCA）、IAST 能力，以及 Go/Python 等其他语言。

下一章：[需求与范围](02-需求与范围.md)
