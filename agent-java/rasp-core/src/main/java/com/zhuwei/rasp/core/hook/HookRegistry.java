package com.zhuwei.rasp.core.hook;

import com.zhuwei.rasp.core.engine.CheckType;
import com.zhuwei.rasp.core.hook.HookPoint.Kind;
import com.zhuwei.rasp.core.hook.HookPoint.ParamExtractor;

import java.io.File;
import java.io.ObjectStreamClass;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * All hook points of this agent version. Adding a hook = adding one entry here.
 * Hook ids are array indexes, so dispatch in {@link RaspSpyHandler} is O(1).
 */
public final class HookRegistry {

    private static final List<HookPoint> HOOKS = new ArrayList<>();
    private static HookPoint[] byId = new HookPoint[0];

    static {
        // ---------------------------------------------------------------- request entry
        add("servlet-javax", Kind.REQUEST_ENTRY, null, "javax/servlet/http/HttpServlet", null,
                new String[]{"service"}, "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V", true, null);
        add("servlet-jakarta", Kind.REQUEST_ENTRY, null, "jakarta/servlet/http/HttpServlet", null,
                new String[]{"service"}, "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V", true, null);

        // ---------------------------------------------------------------- request body (passive copy)
        // Only read(byte[],int,int) and readLine: read() and read(byte[]) normally delegate to them.
        addWithReturnValue("body-javax", Kind.BODY_READ, "javax/servlet/ServletInputStream",
                new String[]{"read", "readLine"}, "([BII)I");
        addWithReturnValue("body-jakarta", Kind.BODY_READ, "jakarta/servlet/ServletInputStream",
                new String[]{"read", "readLine"}, "([BII)I");

        // ---------------------------------------------------------------- async context propagation
        add("tpe-execute", Kind.ASYNC_SUBMIT, null, "java/util/concurrent/ThreadPoolExecutor", null,
                new String[]{"execute"}, "(Ljava/lang/Runnable;)V", false, null);
        add("tpe-before", Kind.ASYNC_BEFORE, null, "java/util/concurrent/ThreadPoolExecutor", null,
                new String[]{"beforeExecute"}, "(Ljava/lang/Thread;Ljava/lang/Runnable;)V", false, null);
        add("tpe-after", Kind.ASYNC_AFTER, null, "java/util/concurrent/ThreadPoolExecutor", null,
                new String[]{"afterExecute"}, "(Ljava/lang/Runnable;Ljava/lang/Throwable;)V", false, null);

        // ---------------------------------------------------------------- command
        add("process-start", Kind.SINK, CheckType.COMMAND, "java/lang/ProcessImpl", null,
                new String[]{"start"}, "([Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;[Ljava/lang/ProcessBuilder$Redirect;Z)Ljava/lang/Process;",
                false, (self, args) -> {
                    String[] cmd = (String[]) args[0];
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("command", cmd == null ? "" : String.join(" ", cmd));
                    p.put("argv", cmd == null ? Collections.emptyList() : Arrays.asList(cmd));
                    p.put("directory", args[2]);
                    return p;
                });

        // ---------------------------------------------------------------- file
        add("file-read", Kind.SINK, CheckType.FILE_READ, "java/io/FileInputStream", null,
                new String[]{"<init>"}, "(Ljava/io/File;)V", false, fileExtractor());
        add("file-write", Kind.SINK, CheckType.FILE_WRITE, "java/io/FileOutputStream", null,
                new String[]{"<init>"}, "(Ljava/io/File;Z)V", false, fileExtractor());

        // ---------------------------------------------------------------- ssrf
        add("url-open", Kind.SINK, CheckType.SSRF, "java/net/URL", null,
                new String[]{"openConnection"}, "(*", false, (self, args) -> {
                    URL u = (URL) self;
                    String proto = u.getProtocol();
                    if (!"http".equals(proto) && !"https".equals(proto)) {
                        return null; // file:, jar:, jrt: ... are used internally by class loading
                    }
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("url", u.toString());
                    p.put("protocol", proto);
                    p.put("hostname", u.getHost());
                    p.put("port", u.getPort() == -1 ? u.getDefaultPort() : u.getPort());
                    return p;
                });

        // ---------------------------------------------------------------- deserialization
        add("ois-resolve", Kind.SINK, CheckType.DESERIALIZATION, "java/io/ObjectInputStream", null,
                new String[]{"resolveClass"}, "(Ljava/io/ObjectStreamClass;)Ljava/lang/Class;", false, (self, args) -> {
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("clazz", ((ObjectStreamClass) args[0]).getName());
                    return p;
                });

        // ---------------------------------------------------------------- jndi
        add("jndi-lookup", Kind.SINK, CheckType.JNDI, "javax/naming/InitialContext", null,
                new String[]{"lookup"}, "(Ljava/lang/String;)Ljava/lang/Object;", false, (self, args) -> {
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("name", args[0]);
                    return p;
                });

        // ---------------------------------------------------------------- sql (any JDBC driver)
        ParamExtractor sql = (self, args) -> {
            if (!(args.length > 0 && args[0] instanceof String)) {
                return null;
            }
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("query", args[0]);
            p.put("driver", self == null ? "" : self.getClass().getName());
            return p;
        };
        add("jdbc-statement", Kind.SINK, CheckType.SQL, null, "java/sql/Statement",
                new String[]{"execute", "executeQuery", "executeUpdate", "executeLargeUpdate", "addBatch"},
                "(Ljava/lang/String;*", false, sql);
        add("jdbc-prepare", Kind.SINK, CheckType.SQL, null, "java/sql/Connection",
                new String[]{"prepareStatement", "prepareCall"}, "(Ljava/lang/String;*", false, sql);

        byId = HOOKS.toArray(new HookPoint[0]);
    }

    private HookRegistry() { }

    private static void add(String name, Kind kind, CheckType type, String className, String iface,
                            String[] methods, String desc, boolean exit, ParamExtractor ex) {
        HOOKS.add(new HookPoint(HOOKS.size(), name, kind, type, className, iface, methods, desc, exit, false, ex));
    }

    private static void addWithReturnValue(String name, Kind kind, String iface, String[] methods, String desc) {
        HOOKS.add(new HookPoint(HOOKS.size(), name, kind, null, null, iface, methods, desc, false, true, null));
    }

    private static ParamExtractor fileExtractor() {
        return (self, args) -> {
            File f = (File) args[0];
            if (f == null) {
                return null;
            }
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("path", f.getPath());
            String real;
            try {
                real = f.getCanonicalPath();
            } catch (Exception e) {
                real = f.getAbsolutePath();
            }
            p.put("realpath", real);
            return p;
        };
    }

    public static List<HookPoint> all() {
        return Collections.unmodifiableList(HOOKS);
    }

    public static HookPoint get(int id) {
        return id >= 0 && id < byId.length ? byId[id] : null;
    }
}
