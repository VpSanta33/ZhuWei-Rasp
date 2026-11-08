package com.zhuwei.rasp.launcher;

import com.sun.tools.attach.AgentLoadException;
import com.sun.tools.attach.AttachNotSupportedException;
import com.sun.tools.attach.VirtualMachine;
import com.sun.tools.attach.VirtualMachineDescriptor;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Command line tool for dynamic injection into a running JVM (no restart needed).
 *
 * <pre>
 * java -jar rasp-launcher.jar list
 * java -jar rasp-launcher.jar status &lt;pid&gt;
 * java -jar rasp-launcher.jar attach &lt;pid&gt; [--app NAME] [--env ENV]
 * java -jar rasp-launcher.jar detach &lt;pid&gt;
 * </pre>
 *
 * Must run as the same OS user as the target JVM, with a full JDK (module jdk.attach).
 * This class is only used in the tool process; it is never loaded inside the target JVM.
 */
public final class AttachMain {

    private static final String LOADED_FLAG = "zhuwei.rasp.loaded";
    private static final int MIN_JAVA = 11;

    private AttachMain() { }

    public static void main(String[] args) {
        int code;
        try {
            code = run(args);
        } catch (NoClassDefFoundError e) {
            System.err.println("错误：当前 Java 不包含 jdk.attach 模块（可能是 JRE）。请使用完整 JDK 运行本工具，"
                    + "最好与目标进程使用同一个 JDK。");
            code = 3;
        }
        System.exit(code);
    }

    static int run(String[] args) {
        if (args.length == 0) {
            usage();
            return 2;
        }
        switch (args[0]) {
            case "list":
                return list();
            case "status":
                return withPid(args, AttachMain::status);
            case "attach":
                return withPid(args, pid -> attach(pid, agentArgs(args)));
            case "detach":
                return withPid(args, AttachMain::detach);
            default:
                usage();
                return 2;
        }
    }

    interface PidCommand {
        int run(String pid) throws Exception;
    }

    private static int withPid(String[] args, PidCommand cmd) {
        if (args.length < 2 || !args[1].matches("\\d+")) {
            System.err.println("缺少或无效的 pid");
            usage();
            return 2;
        }
        String pid = args[1];
        if (pid.equals(String.valueOf(ProcessHandle.current().pid()))) {
            System.err.println("不能对工具自身进程操作");
            return 2;
        }
        try {
            return cmd.run(pid);
        } catch (AttachNotSupportedException e) {
            System.err.println("无法连接进程 " + pid + "：" + e.getMessage());
            System.err.println("请确认：进程存在且是 HotSpot/OpenJ9 JVM；本工具与目标进程是同一个系统用户；"
                    + "目标进程未使用 -XX:+DisableAttachMechanism。");
            return 1;
        } catch (AgentLoadException e) {
            System.err.println("Agent 加载失败：" + e.getMessage());
            System.err.println("如果目标使用了 -XX:-EnableDynamicAgentLoading，需要改为启动参数方式（-javaagent）接入。");
            return 1;
        } catch (Exception e) {
            System.err.println("操作失败：" + e);
            return 1;
        }
    }

    // ------------------------------------------------------------------ commands

    private static int list() {
        String self = String.valueOf(ProcessHandle.current().pid());
        System.out.printf("%-8s %s%n", "PID", "MAIN CLASS / JAR");
        for (VirtualMachineDescriptor d : VirtualMachine.list()) {
            if (d.id().equals(self)) {
                continue;
            }
            String name = d.displayName().isEmpty() ? "(unknown)" : d.displayName();
            System.out.printf("%-8s %s%n", d.id(), name.length() > 120 ? name.substring(0, 120) + "..." : name);
        }
        System.out.println("查看某个进程是否已注入：status <pid>");
        return 0;
    }

    private static int status(String pid) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            Properties p = vm.getSystemProperties();
            System.out.println("pid:           " + pid);
            System.out.println("java.version:  " + p.getProperty("java.version"));
            System.out.println("java.vm.name:  " + p.getProperty("java.vm.name"));
            System.out.println("user.name:     " + p.getProperty("user.name"));
            System.out.println("RASP loaded:   " + (p.getProperty(LOADED_FLAG) != null ? "yes" : "no"));
            return 0;
        } finally {
            vm.detach();
        }
    }

    private static int attach(String pid, String agentArgs) throws Exception {
        String jar = selfJar();
        File home = new File(jar).getParentFile();
        if (!new File(home, "rasp-core.jar").isFile() || !new File(home, "rasp-bootstrap.jar").isFile()) {
            System.err.println("安装目录不完整：" + home + " 下缺少 rasp-core.jar 或 rasp-bootstrap.jar");
            return 1;
        }
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            Properties p = vm.getSystemProperties();
            if (p.getProperty(LOADED_FLAG) != null) {
                System.out.println("进程 " + pid + " 已经加载了 RASP，无需重复注入（如需升级，请先 detach）");
                return 0;
            }
            int major = javaMajor(p.getProperty("java.specification.version"));
            if (major < MIN_JAVA) {
                System.err.println("目标进程 Java 版本为 " + p.getProperty("java.version") + "，当前 Agent 需要 Java " + MIN_JAVA + "+");
                return 1;
            }
            if (major >= 21) {
                System.out.println("提示：Java 21+ 会在目标进程输出一条 \"A Java agent has been loaded dynamically\" 警告，属正常现象。");
            }
            System.out.println("正在注入 " + pid + "（" + p.getProperty("java.version") + "），安装目录 " + home + " ...");
            vm.loadAgent(jar, agentArgs);
            // agentmain runs synchronously; the launcher sets the flag only when the core started
            if (vm.getSystemProperties().getProperty(LOADED_FLAG) != null) {
                System.out.println("注入成功。日志：" + new File(home, "logs/rasp.log"));
                return 0;
            }
            System.err.println("Agent 已加载但核心未启动，请查看目标进程的标准错误输出和 " + new File(home, "logs/rasp.log"));
            return 1;
        } finally {
            vm.detach();
        }
    }

    private static int detach(String pid) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(pid);
        try {
            if (vm.getSystemProperties().getProperty(LOADED_FLAG) == null) {
                System.out.println("进程 " + pid + " 未加载 RASP");
                return 0;
            }
            vm.loadAgent(selfJar(), "uninstall");
            if (vm.getSystemProperties().getProperty(LOADED_FLAG) == null) {
                System.out.println("已卸载：检测已停止，被增强的类已恢复为原始字节码。");
                return 0;
            }
            System.err.println("卸载可能未完成，请查看目标进程日志");
            return 1;
        } finally {
            vm.detach();
        }
    }

    // ------------------------------------------------------------------ helpers

    /** --app / --env become launcher agent args ("app.name=x;app.env=y"). */
    static String agentArgs(String[] args) {
        List<String> kv = new ArrayList<>();
        for (int i = 2; i + 1 < args.length; i += 2) {
            String v = args[i + 1];
            if (v.contains(";") || v.contains("=")) {
                throw new IllegalArgumentException("参数值不能包含 ; 或 =：" + v);
            }
            switch (args[i]) {
                case "--app": kv.add("app.name=" + v); break;
                case "--env": kv.add("app.env=" + v); break;
                default: throw new IllegalArgumentException("未知参数：" + args[i]);
            }
        }
        return String.join(";", kv);
    }

    static int javaMajor(String spec) {
        if (spec == null) {
            return 0;
        }
        String s = spec.startsWith("1.") ? spec.substring(2) : spec;
        int dot = s.indexOf('.');
        try {
            return Integer.parseInt(dot > 0 ? s.substring(0, dot) : s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String selfJar() throws Exception {
        File f = new File(AttachMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        if (!f.isFile()) {
            throw new IOException("请通过 java -jar rasp-launcher.jar 运行本工具");
        }
        return f.getAbsolutePath();
    }

    private static void usage() {
        System.err.println("用法：");
        System.err.println("  java -jar rasp-launcher.jar list                                  列出本用户的 Java 进程");
        System.err.println("  java -jar rasp-launcher.jar status <pid>                          查看是否已注入");
        System.err.println("  java -jar rasp-launcher.jar attach <pid> [--app 名称] [--env 环境]  动态注入");
        System.err.println("  java -jar rasp-launcher.jar detach <pid>                          卸载并恢复原始字节码");
    }
}
