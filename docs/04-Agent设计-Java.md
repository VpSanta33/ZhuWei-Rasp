# 第 4 章　Agent 设计（Java）

本章是整个项目技术难度最高的部分。

## 4.1 基础：Java Instrumentation

JDK 从 1.5 开始提供 `java.lang.instrument`，允许 Agent 在类加载时或加载后修改字节码。

| 方式 | 入口方法 | 时机 | 说明 |
|---|---|---|---|
| 静态加载 | `public static void premain(String args, Instrumentation inst)` | `main` 之前 | 启动参数 `-javaagent:xxx.jar=args`，最稳定 |
| 动态 attach | `public static void agentmain(String args, Instrumentation inst)` | 运行中 | 通过 `com.sun.tools.attach.VirtualMachine.attach(pid).loadAgent(jar)` 注入，不用重启 |

jar 的 `MANIFEST.MF` 示例：

```
Premain-Class: com.zhuwei.rasp.launcher.AgentLauncher
Agent-Class: com.zhuwei.rasp.launcher.AgentLauncher
Can-Redefine-Classes: true
Can-Retransform-Classes: true
Can-Set-Native-Method-Prefix: true
Boot-Class-Path: rasp-bootstrap.jar     # 可选，也可以在代码中 appendToBootstrapClassLoaderSearch
```

核心 API：

- `inst.addTransformer(ClassFileTransformer, canRetransform=true)`：注册字节码转换器。
- `inst.retransformClasses(Class...)`：对已经加载的类重新执行转换（attach 场景必须用）。
- `inst.appendToBootstrapClassLoaderSearch(JarFile)`：把 jar 加到 Bootstrap 类路径。
- `inst.setNativeMethodPrefix(transformer, prefix)`：用于 Hook native 方法（例如 `forkAndExec`）。
- `inst.redefineModule(...)`：JDK 9+ 打开模块访问权限。

**retransform 的限制**：不能新增/删除字段和方法，不能修改方法签名和继承关系，只能修改方法体。所以插桩方式必须是“在方法体中插入对外部静态方法的调用”。

## 4.2 类加载与隔离设计

### 4.2.1 为什么需要隔离

- Agent 用到的 ASM、JSON、HTTP 库可能和业务依赖版本冲突。
- 业务的类加载器结构复杂（Tomcat WebappClassLoader、OSGi、Spring Boot LaunchedURLClassLoader），Agent 的类不能“污染”业务。
- 卸载 Agent 时需要能回收 core 的所有类。

### 4.2.2 三层结构

```
BootstrapClassLoader
 ├── java.*（JDK 类）
 └── rasp-bootstrap.jar      ← Spy、HookCallback 接口、RaspBlockException
        ▲ 所有被插桩类（包括 java.lang.ProcessImpl）都能看到这里的类
        │
AppClassLoader ── 业务类、rasp-launcher.jar（仅入口类）
        │
RaspClassLoader（自定义，parent = null 或 PlatformCL）
 └── rasp-core.jar + shade 后的依赖 ← 全部实现，与业务完全隔离
```

**原理**：插桩代码要被 `java.io.FileInputStream`（由 Bootstrap 加载）这样的类调用，而 Bootstrap 加载的类只能看见 Bootstrap 中的类。所以：

1. 插桩代码只调用 `com.zhuwei.rasp.bootstrap.Spy` 的静态方法（位于 Bootstrap）。
2. `Spy` 内部持有一个由 core 注入的回调对象（接口定义在 bootstrap 中，实现在 core 中），把调用转发给 core。
3. core 由 `RaspClassLoader` 加载，业务类看不到它，也就不会发生冲突。

### 4.2.3 Spy 示例

```java
// rasp-bootstrap 中，尽可能精简、稳定，一旦发布几乎不改
package com.zhuwei.rasp.bootstrap;

public final class Spy {
    private static volatile SpyHandler handler = SpyHandler.NOP;

    public static void install(SpyHandler h) { handler = h; }
    public static void uninstall() { handler = SpyHandler.NOP; }

    /** 方法进入时调用；返回非 null 表示需要阻断（由插桩代码抛出） */
    public static Throwable onEnter(int hookId, Object self, Object[] args) {
        try {
            return handler.onEnter(hookId, self, args);
        } catch (Throwable t) {
            return null;              // 绝不影响业务
        }
    }

    public static Throwable onReturn(int hookId, Object self, Object ret) {
        try { return handler.onReturn(hookId, self, ret); } catch (Throwable t) { return null; }
    }

    public static void onThrow(int hookId, Object self, Throwable t) {
        try { handler.onThrow(hookId, self, t); } catch (Throwable ignore) { }
    }
}
```

`RaspBlockException` 也定义在 bootstrap 中，继承 `RuntimeException`（或者 `SecurityException`，可以更好地让上层框架识别）。

## 4.3 字节码增强

### 4.3.1 插桩模板（ASM AdviceAdapter）

对目标方法做如下逻辑等价的改写：

```java
// 原方法
public ResultSet executeQuery(String sql) { ...原逻辑... }

// 增强后（伪代码）
public ResultSet executeQuery(String sql) {
    Throwable __block = Spy.onEnter(HOOK_SQL_QUERY, this, new Object[]{sql});
    if (__block != null) throw (RuntimeException) __block;
    ...原逻辑...
}
```

实现要点：

1. 使用 `AdviceAdapter.onMethodEnter` 插入代码；参数装箱为 `Object[]`。
2. `hookId` 是 int 常量，core 通过它找到对应的处理器，避免字符串比较。
3. 计算栈帧：使用 `ClassWriter.COMPUTE_FRAMES` 时需要覆写 `getCommonSuperClass`，**不能用 `Class.forName` 加载业务类**（会触发类加载导致死锁或副作用）。应通过读取 class 字节自行解析继承关系，或改用 `COMPUTE_MAXS` 并手动维护帧。
4. 只修改匹配到的方法；未命中的类直接 `return null`（表示不修改），减少开销。
5. 转换失败时 catch 并返回 `null`，记录日志，**绝不能抛出异常**。
6. 对每个增强过的类做标记（记录在 Agent 内部的 Set 中），防止重复增强；卸载时用于还原。

### 4.3.2 Hook 匹配方式

| 匹配类型 | 用途 | 示例 |
|---|---|---|
| 精确类名 + 方法名 + 描述符 | JDK 类 | `java/lang/ProcessImpl#start` |
| 接口实现类 | JDBC 驱动 | 实现了 `java.sql.Statement` 的所有类的 `execute*` 方法 |
| 父类子类 | Servlet | `javax.servlet.http.HttpServlet` 的子类 |
| 注解 | Spring Controller（内存马检测时） | `@RequestMapping` |

接口/父类匹配需要在 transform 时解析 class 的 `interfaces` 和 `superName`，并维护一个“已知实现类”缓存。对于间接实现（A extends B implements Statement）需要递归解析。建议通过 `ClassLoader.getResource(xxx.class)` 读取父类字节码来判断，而不是加载父类。

### 4.3.3 Native 方法 Hook

`java.lang.UNIXProcess.forkAndExec`（JDK 8）、`java.lang.ProcessImpl.forkAndExec`（JDK 9+）是 native 方法，攻击者可能绕过 `ProcessBuilder.start` 直接反射调用它。处理方式：

1. `inst.setNativeMethodPrefix(transformer, "$$rasp$$")`。
2. 把 native 方法 `forkAndExec` 重命名为 `$$rasp$$forkAndExec`（仍为 native），再新增一个同名的 Java 方法 `forkAndExec`，在其中先调用 Spy，再调用前缀方法。
3. 注意：新增方法只能在**类首次加载时**进行（retransform 不允许增加方法），所以必须用 premain 方式；attach 场景下退而求其次，Hook `ProcessImpl.start` / `ProcessBuilder.start`。

### 4.3.4 JDK 9+ 模块系统

- 在 `java.base` 中插入对 `Spy` 的调用：Spy 位于 Bootstrap 的 unnamed module，`java.base` 默认可以读取 unnamed module（通过 `appendToBootstrapClassLoaderSearch` 加入的类属于 Bootstrap 的 unnamed module）。如果实际遇到 `IllegalAccessError`，需要调用 `inst.redefineModule` 让 `java.base` reads 该 module。
- core 反射访问 JDK 内部字段（如 `ProcessImpl` 私有字段）时，需要 `redefineModule` 加上 `extraOpens`，否则 JDK 17+ 会报 `InaccessibleObjectException`。

## 4.4 Hook 点清单（首版）

> 各中间件、驱动的类名差异很大，实际开发时需要逐个验证。下面是主要入口，完整清单维护在 `rasp-core/hook/HookRegistry`。

### 4.4.1 请求入口（Source）

| 类 / 接口 | 方法 | 作用 |
|---|---|---|
| `javax.servlet.http.HttpServlet` / `jakarta.servlet.http.HttpServlet` | `service(ServletRequest, ServletResponse)` | 创建/销毁请求上下文 |
| `org.apache.catalina.core.ApplicationFilterChain` | `doFilter` | Tomcat 优先，比 Servlet 更早 |
| `javax/jakarta.servlet.ServletInputStream` 实现类 | `read*` | 采集请求 Body（需要缓存，有大小上限） |
| `ServletRequest` 实现类 | `getParameter*` / `getInputStream` | 获取参数（避免提前消费 Body，见 4.5） |
| Spring WebFlux `DispatcherHandler` | `handle` | 响应式框架入口（P1） |
| Dubbo `ProxyFactory`/`Filter`、gRPC `ServerCall.Listener` | — | RPC 入口（P2） |

### 4.4.2 敏感函数（Sink）

| 检测类型 | Hook 点 |
|---|---|
| SQL | `java.sql.Statement` / `PreparedStatement` 实现类（MySQL `com.mysql.cj.jdbc.StatementImpl`/`ClientPreparedStatement`、Oracle `oracle.jdbc.driver.OracleStatement`、PG `org.postgresql.jdbc.PgStatement`、达梦 `dm.jdbc.driver.DmdbStatement`、金仓 `com.kingbase8.jdbc.KbStatement` 等）的 `execute`/`executeQuery`/`executeUpdate`/`addBatch`；`Connection.prepareStatement(sql)` |
| 命令执行 | `java.lang.ProcessImpl.start`、`forkAndExec`（native）、`java.lang.UNIXProcess` 构造函数（JDK 8）、Windows `ProcessImpl.create` |
| 文件读 | `java.io.FileInputStream(File)`、`RandomAccessFile`、`sun.nio.ch.FileChannelImpl`、`java.nio.file.Files#newInputStream/readAllBytes` 等（建议 Hook `sun.nio.fs.UnixFileSystemProvider.newByteChannel`） |
| 文件写 | `java.io.FileOutputStream(File, boolean)`、NIO `newByteChannel`（带 WRITE 选项） |
| 目录遍历 | `java.io.File.list`/`listFiles`、`Files.newDirectoryStream` |
| 删除/重命名 | `java.io.File.delete/renameTo`、`Files.delete/move` |
| SSRF | `java.net.URL.openConnection`、`sun.net.www.protocol.http.HttpURLConnection.connect`、Apache HttpClient `execute`、OkHttp `RealCall`、`java.net.Socket.connect`（兜底） |
| DNS（SSRF 辅助） | `java.net.InetAddress.getAllByName` |
| 反序列化 | `java.io.ObjectInputStream.resolveClass`、`resolveProxyClass`；Fastjson `ParserConfig.checkAutoType`；Jackson `BeanDeserializerFactory.createBeanDeserializer`；XStream `XStream.unmarshal`；Hessian `SerializerFactory.getDeserializer` |
| JNDI | `javax.naming.InitialContext.lookup`、`com.sun.jndi.ldap.LdapCtx`、`com.sun.jndi.rmi.registry.RegistryContext.lookup` |
| 表达式 | `ognl.Ognl.parseExpression`/`OgnlParser`、`org.springframework.expression.spel.standard.SpelExpressionParser.parseExpression`、`javax.el.ExpressionFactory.createValueExpression`、MVEL、Groovy `GroovyShell.evaluate`、`javax.script.ScriptEngine.eval` |
| XXE | `com.sun.org.apache.xerces.internal.impl.XMLEntityManager.startEntity`（可拿到实体 URL） |
| 类加载（内存马） | `java.lang.ClassLoader.defineClass`、`sun.misc.Unsafe.defineAnonymousClass`、`java.lang.invoke.MethodHandles.Lookup.defineClass` |
| 组件注册（内存马） | Tomcat `StandardContext.addFilterDef/addServletMappingDecoded/addApplicationEventListener`、Spring `AbstractHandlerMethodMapping.registerMapping`、Jetty/Undertow 对应方法 |
| 反射（辅助） | `java.lang.reflect.Method.invoke`（开销大，默认关闭，仅在特定栈下启用） |

## 4.5 请求上下文（RequestContext）

```java
final class RequestContext {
    long   startNanos;
    String requestId;               // 生成或复用 traceId
    String method, uri, queryString, remoteAddr, realIp;   // realIp 来自 XFF 等头（可配置）
    Map<String, String[]> params;   // 懒加载
    Map<String, String>   headers;  // 懒加载、大小受限
    byte[] bodySnapshot;            // 只缓存前 N KB（默认 64KB）
    String contentType;
    Object nativeRequest, nativeResponse;   // 持有原始对象（弱引用 or 请求结束清空）
    List<String> userInputs;        // 扁平化后的所有用户输入值（含解码后的 JSON 值）
    int  hookCount;                 // 防止单请求无限检测
    boolean ignored;                // 命中 URL 白名单则整请求跳过
}
```

关键注意点：

1. **ThreadLocal 生命周期**：入口 `onEnter` 时创建（嵌套的 Filter/Servlet 只在最外层创建），`onReturn`/`onThrow` 时在最外层清理。线程池复用时如果残留旧上下文，会造成误报和内存泄漏。
2. **不提前消费请求体**：读取 `getParameter` 会触发表单解析，可能改变业务行为（例如业务自己要读 InputStream）。正确做法是 Hook `ServletInputStream.read` 被动地“旁路复制”业务实际读到的数据，参数在业务调用过 `getParameter` 之后再取，或在检测时才懒加载。
3. **异步线程**：`@Async`、线程池、CompletableFuture 中的 Sink 调用拿不到 ThreadLocal。首版可以接受（此时检测退化为“无请求上下文”模式，只做基于参数和栈的检测）；二期 Hook `ThreadPoolExecutor.execute` 等实现上下文传递（参考 TransmittableThreadLocal）。
   **MVP 已实现**，任务对象从不被包装或替换：
   - ThreadPoolExecutor：`execute` 记录提交方上下文快照（弱引用、按对象身份），`beforeExecute/afterExecute` 安装与清除。
   - ForkJoinPool：`ForkJoinTask` 构造时记录，`doExec()` 期间安装（JDK 11–17 返回 int，新版本返回 void，按前缀匹配描述符）；工作线程会内联执行其他任务，因此用每线程栈保存/恢复外层上下文。
   - `new Thread(runnable)`：仅普通 `java.lang.Thread` 实例，`start()` 时记录、`run()` 期间安装。
   - 原则：异步上下文永远不覆盖真实的请求上下文；进入/退出无论开关与熔断状态都成对执行，保证栈平衡。
4. **用户输入提取**：对参数、Header（白名单列表，如 UA、Referer、Cookie 值）、JSON Body 的所有叶子值、Multipart 文件名做扁平化，提取出 `userInputs`，并缓存在上下文中供各个检测项复用。
5. **防重入**：Agent 自身执行时（例如上报网络请求、读规则文件）也会触发 Hook。用一个 ThreadLocal `inRasp` 标志位，Agent 内部代码执行期间跳过所有 Hook。

## 4.6 阻断实现

1. Sink Hook 判定为 `BLOCK` → `Spy.onEnter` 返回 `RaspBlockException` → 插桩代码 `throw`。
2. 异常向上冒泡，业务代码可能 catch 住它（例如 `catch (Exception e)`）。因此：
   - 在请求入口 Hook 的 `onReturn` 中检查上下文 `blocked` 标志，如果已经判定阻断但异常被吞掉，就直接**重置响应并输出拦截页面**（如果响应尚未提交）。
   - 如果响应已经提交（`isCommitted()`），只能记录日志，关键是 Sink 已经没有执行。
3. 拦截页面：可配置 HTTP 状态码（默认 403）、HTML/JSON 模板（根据 `Accept` 头选择），包含 `request_id` 便于排查。
4. 无请求上下文时（定时任务、MQ 消费），阻断就是抛异常。

## 4.7 生命周期管理

### 4.7.1 启动

```
premain/agentmain
  ├─ 防重复加载检查（System property 标记）
  ├─ 解析参数、定位 RASP_HOME
  ├─ 检查运行环境（JDK 版本、是否在黑名单进程如 jps/jstack 中）
  ├─ appendToBootstrapClassLoaderSearch(rasp-bootstrap.jar)
  ├─ new RaspClassLoader(rasp-core.jar) → 反射调用 CoreEngine.start(inst, args)
  │     ├─ 加载本地配置 / 缓存的规则
  │     ├─ 启动通信线程（daemon 线程，不阻塞启动）
  │     ├─ Spy.install(handler)
  │     ├─ inst.addTransformer(...)
  │     └─ 对已加载的目标类 retransform（attach 场景）
  └─ 全程 try/catch(Throwable)，失败则打印日志并放弃，业务照常启动
```

**启动不阻塞**：注册 Server、拉规则都在后台线程执行；首次启动使用本地缓存的规则或内置默认规则。

### 4.7.2 卸载（attach 模式）

1. `Spy.uninstall()` → 所有 Hook 立即变为空操作。
2. `inst.removeTransformer` 并对增强过的类执行 `retransformClasses`（此时 transformer 不再修改，类恢复原始字节码）。
3. 停止所有 Agent 线程，清理 ThreadLocal 引用，关闭 RaspClassLoader，置空静态引用，让 core 的类可以被 GC。
4. bootstrap 中的 Spy 类无法卸载，所以必须保证它足够小，并且在重新 attach 时兼容。

### 4.7.3 热更新

- **规则热更新**：无需 retransform，替换引擎中的规则对象即可（使用 volatile 引用 + 不可变对象）。
- **Hook 点变更**：需要 retransform 相关类，属于重操作，只在升级 Agent 版本时进行。
- **Agent 升级**：attach 模式可以“卸载旧版 + attach 新版”；premain 模式需要重启生效（可以在平台提示用户）。

## 4.8 Agent 线程模型

| 线程 | 数量 | 职责 |
|---|---|---|
| `rasp-heartbeat` | 1 | 心跳、拉配置/规则 |
| `rasp-reporter` | 1～2 | 从有界队列中批量取告警/日志上报，失败时写本地文件、指数退避 |
| `rasp-monitor` | 1 | 自监控：CPU、耗时统计、熔断判定 |
| `rasp-scanner` | 1 | 低频任务：依赖扫描、内存马周期扫描 |

全部设为 daemon 线程，并设置名称前缀，便于在 jstack 中识别。

## 4.9 配置文件 `conf/rasp.yaml`

```yaml
server:
  url: https://rasp.company.com
  app_key: "xxxx"            # 应用级 key，由平台生成
  app_secret: "xxxx"
  verify_tls: true
app:
  name: order-service        # 未配置时使用 -Drasp.app.name 或环境变量 RASP_APP_NAME
  env: prod
log:
  level: INFO
  path: /opt/rasp/logs
  max_size_mb: 100
  max_files: 5
runtime:
  mode: monitor              # 初始默认模式：off / monitor / block（Server 下发的配置会覆盖）
  body_max_bytes: 65536     # 请求体采集上限（0 关闭，最大 1 MiB）；MVP 中位于策略 policy.json
  async_context: true       # 线程池任务继承提交线程的请求上下文
  read_form_params: false   # 是否调用 getParameterMap 读取表单参数（会触发容器解析请求体）
  report_queue_size: 2000
```

MVP 另有 `sca.enabled`（默认 true）、`sca.initial_delay_sec`（默认 30）、`sca.interval_min`（默认 10）控制组件扫描。

优先级：Server 下发 > JVM 参数 `-Drasp.*` > 环境变量 `RASP_*` > 配置文件 > 默认值。

## 4.10 Agent 日志

- 使用自研的极简 logger（不要依赖业务的 log4j/logback，避免冲突和递归 Hook）。
- 日志文件：`rasp.log`（运行）、`alarm.log`（告警本地留存，Server 不可达时用于补报）、`policy.log`（基线），按大小滚动。
- 日志同样不能写满磁盘：总大小受限。

下一章：[检测引擎与规则](05-检测引擎与规则.md)

## 附：JDK 8 兼容（MVP 已实现）

- Agent 三个 jar 以 Java 8 字节码（major 52）编译（`maven.compiler.release=8`；测试代码用 11）。
- 模块系统 API（`Module`、`Instrumentation.redefineModule`、`getPlatformClassLoader`）集中在 `util/Jdk`，通过反射调用，JDK 8 上为空操作；`ProcessHandle` 改用 RuntimeMXBean 取 pid。
- `RaspTransformer` 实现 Java 8 的 5 参数 `transform`；JDK 9+ 上默认的 `transform(Module, …)` 委托给它，命名模块在启动时统一打开对 Spy 的读权限。
- attach 工具通过反射使用 `com.sun.tools.attach`：JDK 9+ 来自 `jdk.attach` 模块，JDK 8 自动加载 `$JAVA_HOME/lib/tools.jar`（`java -jar` 无法追加 classpath）。
- 兼容性测试：`agent-java/compat-app`（Java 8 + Tomcat 9 / javax.servlet）+ `smoke-test.sh`，CI 在 JDK 8、11、17、21 上运行：启动注入、javax.servlet Hook、请求线程/线程池/CompletableFuture 告警、命令执行 Hook、动态 attach/detach。
