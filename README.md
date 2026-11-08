# ZhuWei-RASP

> 版本：v0.1.0（MVP）　日期：2026-11-08

公司 RASP（运行时应用自我保护）平台：Java Agent + 管理平台 + 设计文档。

## 项目状态

**MVP 已完成，适合 POC 与内部试点，尚不能直接作为生产防护上线。** 端到端链路（接入 → Hook → 检测 → 告警/阻断 → 平台管理 → 策略签名下发）已在 demo 应用上验证；单元测试全部通过；粗测 Agent 开销在测量误差范围内。

上线前的建议顺序：

1. 安全团队按 `Detector` 接口补齐各攻击类型的专用检测算法（第 5 章）——这是当前最关键的缺口；
2. 选非核心应用在**观察模式**下试点，统计误报与性能影响；
3. 补齐 RBAC 多用户；
4. 按第 8 章的灰度流程逐步开启阻断。

## 环境要求

| 组件 | 要求 |
|---|---|
| 被保护的 Java 应用 | JDK 11+（JDK 21+ 动态 attach 会打印 JEP 451 警告，建议用 `-XX:+EnableDynamicAgentLoading` 或改用 `-javaagent`） |
| 构建 Agent | JDK 17+、Maven 3.9+ |
| 构建平台 | Go 1.27+（纯 Go SQLite，`CGO_ENABLED=0` 即可交叉编译） |
| 运行平台 | 单二进制 + 一个 SQLite 文件；生产环境请放在 TLS 之后（`-tls-cert/-tls-key` 或反向代理） |

## 代码结构

```
agent-java/            Maven 多模块（需要 JDK 11+ 运行，用 JDK 17+ 构建）
  rasp-launcher/       -javaagent 入口，负责建立类加载器隔离
  rasp-bootstrap/      注入 BootstrapClassLoader 的 Spy 桩类（尽量小、稳定）
  rasp-core/           Hook 定义、ASM 字节码增强、请求上下文、规则引擎、策略、熔断、上报
  demo-app/            内嵌 Tomcat 演示应用，用于端到端验证（只在隔离测试环境使用）
server/                Go 管理平台（单二进制：Agent API + 控制台 API + 内嵌 Web 控制台，SQLite）
deploy/                构建脚本、Agent 配置模板与默认策略
docs/                  设计文档
```

## 快速开始

```bash
./deploy/build.sh
```

```bash
RASP_ADMIN_PASSWORD='换成你的密码' ./dist/rasp-server -listen :8480 -db rasp.db -agent-url http://<服务器地址>:8480
```

1. 浏览器打开 `http://<服务器地址>:8480`，登录后在“应用管理”中新建应用，把生成的配置写入 `dist/rasp/conf/rasp.properties`（其中的 `policy.public_key` 是策略签名公钥；Server 首次启动时在数据库同目录生成私钥 `rasp-sign.key`，请备份）。
2. 把 `dist/rasp` 复制到业务主机的 `/opt/rasp`，在 Java 启动参数中加入 `-javaagent:/opt/rasp/rasp-launcher.jar`。
3. 不配置 `server.url` 时为独立模式：使用 `conf/policy.json`，告警只写入 `logs/alarm.log`。
4. 不重启接入：`/opt/rasp/tools/rasp-attach.sh attach <pid> --app 应用名`，卸载用 `detach <pid>`（需与目标进程同一用户）。
5. 紧急停用：在平台开启“全局紧急开关”，或在主机上创建文件 `/opt/rasp/DISABLE`。

## MVP 实现范围

| 已实现 | 说明 |
|---|---|
| Agent 加载与隔离 | premain 与动态 attach/detach（`rasp-attach.sh`）；Bootstrap/独立 ClassLoader 三层结构；ASM shade；JDK 9+ 模块读权限处理 |
| Hook 点 | Servlet 入口（javax/jakarta）、JDBC Statement/Connection（任意驱动，按接口匹配）、ProcessImpl、FileInputStream/FileOutputStream、URL.openConnection、ObjectInputStream.resolveClass、InitialContext.lookup |
| 检测 | 通用声明式规则引擎（条件：等于/包含/前缀/正则/集合/“包含用户输入”等）；`Detector` 接口供安全团队接入专用算法 |
| 策略 | 关闭/观察/阻断三种模式，按类型设置开关和最高动作，URL 白名单，阻断页（HTML/JSON） |
| 请求上下文 | 请求体被动采集（JSON 扁平化 / 表单 / multipart 文件名，上限 `body_max_bytes`，敏感字段脱敏）；ThreadPoolExecutor 异步任务继承请求上下文（`async_context`） |
| 稳定性 | 全路径异常隔离、防重入、熔断（耗时/异常率）、DISABLE 文件、有界队列 |
| 组件资产（SCA） | Agent 按已加载类的来源 jar 识别组件（pom.properties → MANIFEST → 文件名，支持 Spring Boot 嵌套 jar，附 SHA-1），变化时上报；平台“组件资产”页可筛选、看多版本、导出 CSV |
| 策略签名 | 平台下发的配置用 ECDSA P-256 签名，Agent 用固定公钥验签；绑定应用、防回滚、缓存启动时重新验签；失败保留旧配置并在心跳中上报；支持多公钥轮换 |
| 平台 | 应用/实例/告警/策略/白名单/紧急开关/Webhook 通知/审计；HMAC 签名、防重放 |

**已知限制**：请求体只在业务代码读取时采集（被动拷贝，不预读）；不带 pom/MANIFEST 元数据的 uber jar 只能识别为一个组件。

**尚未实现**（见各章设计）：各攻击类型的专用检测算法（第 5 章，待安全团队编写）；内存马检测；组件漏洞库匹配（目前只有清单，无 CVE 关联）；ForkJoinPool / CompletableFuture 默认池与裸 `new Thread` 的上下文传递；RBAC 多用户与 SSO；ClickHouse/Kafka 的规模化部署形态；JDK 8 支持。

## 开发与测试

```bash
(cd agent-java && mvn -B clean package)   # Agent 构建 + 单元测试（clean 不能省：避免 shade 重复打包）
(cd server && go vet ./... && go test ./...)  # 平台测试
./deploy/build.sh                         # 一次性构建并组装 dist/
```

- `deploy/agent-conf/policy.json` 是默认策略的唯一来源，`build.sh` 会把它复制到 `server/internal/policy/default_policy.json`（两份请勿分别手改）。
- `demo-app` 含故意写成不安全的接口，**只在隔离的测试环境运行**，不要部署到任何可被访问的网络。
- 不要提交 `dist/`、`*.db`、`rasp-sign.key*`（已在 `.gitignore` 中）；签名私钥只放在平台服务器上并单独备份。
- 修改 Agent 与平台之间的协议时，同步更新第 7 章，并保证新 Agent 能连旧平台、旧 Agent 能连新平台。

## 路线图

| 优先级 | 事项 |
|---|---|
| P0 | 专用检测算法（第 5 章，安全团队）；观察模式试点与误报治理 |
| P1 | RBAC 多用户 / SSO；下发阻断配置二次确认；组件漏洞库（CVE）匹配 |
| P2 | ForkJoinPool / CompletableFuture / 裸 Thread 上下文传递；内存马检测；安装/卸载脚本 |
| P3 | ClickHouse/Kafka 规模化部署；JDK 8 支持；其他语言 Agent |

## 设计文档

建议按顺序阅读：先读第 1 章弄清概念，再读第 3、4 章理解核心架构。设计文档描述的是目标形态，与 MVP 的差异以上方“MVP 实现范围”为准。

## 文档目录

| 章节 | 文件 | 内容 | 主要读者 |
|---|---|---|---|
| 1 | [RASP 概述](docs/01-RASP概述.md) | 概念、原理、与 WAF/IAST 的区别、业界方案 | 全员 |
| 2 | [需求与范围](docs/02-需求与范围.md) | 目标、功能/非功能需求、版本范围 | 产品、架构 |
| 3 | [总体架构](docs/03-总体架构.md) | 系统组成、模块划分、技术选型、数据流 | 架构、开发 |
| 4 | [Agent 设计（Java）](docs/04-Agent设计-Java.md) | 注入、字节码增强、类隔离、Hook 点、上下文 | Agent 开发 |
| 5 | [检测引擎与规则](docs/05-检测引擎与规则.md) | **待补充**：检测算法、规则格式与发布流程（目前只有大纲） | 安全研究、Agent 开发 |
| 6 | [管理平台（Server）](docs/06-管理平台-Server.md) | 后端服务、前端功能、数据库设计、API | 平台开发 |
| 7 | [通信协议与数据模型](docs/07-通信协议与数据模型.md) | Agent↔Server 协议、报文格式、告警模型 | 全体开发 |
| 8 | [部署与运维](docs/08-部署与运维.md) | 安装方式、容器/K8s、升级、灰度、降级 | 运维、开发 |
| 9 | [性能、稳定性与自身安全](docs/09-性能稳定性与自身安全.md) | 性能预算、熔断、容错、自身防护 | 全体开发 |
| 10 | [测试方案](docs/10-测试方案.md) | 单元/集成/兼容性/攻防/性能测试 | 测试、开发 |
| 11 | [开发计划与里程碑](docs/11-开发计划与里程碑.md) | 阶段划分、人力、风险 | 管理、全员 |
| 12 | [参考资料](docs/12-参考资料.md) | 开源项目、文章、规范 | 全员 |

## 一句话理解 RASP

WAF 守在应用**门外**，只看 HTTP 流量。RASP 嵌在应用**里面**（比如作为 Java Agent 注入 JVM），在 SQL 执行、命令执行、文件读写、网络请求、反序列化这些**危险函数真正执行前**拦下来检查：“这次调用的参数是不是被用户输入篡改了？”是攻击就阻断，不是就放行。所以 RASP 误报低，也不怕流量混淆和加密，但它和应用跑在同一个进程里，对性能和稳定性要求非常高。

## 关键设计决策（摘要）

1. **先做 Java**：国内企业 Java 应用最多，生态最成熟（参考 OpenRASP、jrasp、jvm-sandbox）。后续再扩展到 Go/Python/Node.js/PHP。
2. **Agent 与检测逻辑分离**：Agent 只负责 Hook 和收集上下文，检测算法写成可热更新的规则/插件，安全团队可以单独迭代。
3. **默认只告警，可以切到阻断**：新接入的应用先在“观察模式”下跑一段时间，误报处理完再开阻断。
4. **自身稳定优先于检测**：任何 Agent 异常都不能影响业务。CPU、内存或耗时超阈值时自动熔断降级。
5. **管理平台**：Go 后端 + Vue3 前端。目标形态是 MySQL 存配置、ClickHouse/Elasticsearch 存告警和日志、Kafka 削峰；MVP 为单二进制 + SQLite，按包划分，后续可沿包边界拆分。
