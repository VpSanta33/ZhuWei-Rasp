package com.zhuwei.rasp.core.util;

import java.lang.instrument.Instrumentation;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * JDK 8 / JDK 9+ compatibility. The agent is compiled for Java 8; module-system APIs (JDK 9+) are called
 * reflectively and become no-ops on JDK 8, where there are no modules to open.
 */
public final class Jdk {

    /** Major Java version: 8, 11, 17, 21, ... */
    public static final int VERSION = parseVersion(System.getProperty("java.specification.version", "1.8"));
    public static final boolean MODULES = VERSION >= 9;

    private Jdk() { }

    static int parseVersion(String spec) {
        try {
            return spec.startsWith("1.") ? Integer.parseInt(spec.substring(2)) : Integer.parseInt(spec.split("\\.")[0]);
        } catch (RuntimeException e) {
            return 8;
        }
    }

    /**
     * Lets every module of the boot layer read the (unnamed) module that holds {@code spyClass}, so woven
     * JDK classes such as java.base or java.naming can call Spy. No-op on JDK 8.
     */
    public static void allowBootModulesToRead(Instrumentation inst, Class<?> spyClass) throws Exception {
        if (!MODULES) {
            return;
        }
        Object spyModule = Class.class.getMethod("getModule").invoke(spyClass);
        Class<?> layerClass = Class.forName("java.lang.ModuleLayer");
        Object boot = layerClass.getMethod("boot").invoke(null);
        @SuppressWarnings("unchecked")
        Set<Object> modules = (Set<Object>) layerClass.getMethod("modules").invoke(boot);
        for (Object m : modules) {
            ensureReads(inst, m, spyModule);
        }
    }

    /** Module of {@code c} (JDK 9+), or null on JDK 8. */
    public static Object moduleOf(Class<?> c) {
        if (!MODULES || c == null) {
            return null;
        }
        try {
            return Class.class.getMethod("getModule").invoke(c);
        } catch (Exception e) {
            return null;
        }
    }

    /** Makes {@code module} read {@code target} if it is a named module that cannot yet. */
    public static void ensureReads(Instrumentation inst, Object module, Object target) throws Exception {
        if (module == null || target == null) {
            return;
        }
        Class<?> mc = Class.forName("java.lang.Module");
        if (!(Boolean) mc.getMethod("isNamed").invoke(module) || (Boolean) mc.getMethod("canRead", mc).invoke(module, target)) {
            return;
        }
        Method redefine = Instrumentation.class.getMethod("redefineModule", mc, Set.class, Map.class, Map.class, Set.class, Map.class);
        redefine.invoke(inst, module, Collections.singleton(target), Collections.emptyMap(), Collections.emptyMap(),
                Collections.emptySet(), Collections.emptyMap());
    }

    /** True when the class is accessible across module boundaries (always true on JDK 8). */
    public static boolean isExported(Class<?> c) {
        if (!MODULES) {
            return true;
        }
        try {
            Object m = Class.class.getMethod("getModule").invoke(c);
            Class<?> mc = m.getClass();
            if (!(Boolean) mc.getMethod("isNamed").invoke(m)) {
                return true;
            }
            String pkg = c.getName().lastIndexOf('.') > 0 ? c.getName().substring(0, c.getName().lastIndexOf('.')) : "";
            return (Boolean) mc.getMethod("isExported", String.class).invoke(m, pkg);
        } catch (Exception e) {
            return false;
        }
    }

    /** The platform class loader (JDK 9+) or the extension class loader (JDK 8). */
    public static ClassLoader platformClassLoader() {
        try {
            return (ClassLoader) ClassLoader.class.getMethod("getPlatformClassLoader").invoke(null);
        } catch (Exception e) {
            return ClassLoader.getSystemClassLoader().getParent();
        }
    }

    /** Current process id; JDK 8 derives it from the runtime MXBean name ("pid@host"). */
    public static long pid() {
        try {
            Class<?> ph = Class.forName("java.lang.ProcessHandle");
            Object current = ph.getMethod("current").invoke(null);
            return (Long) ph.getMethod("pid").invoke(current);
        } catch (Exception e) {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            int at = name.indexOf('@');
            try {
                return Long.parseLong(at > 0 ? name.substring(0, at) : name);
            } catch (NumberFormatException nfe) {
                return -1;
            }
        }
    }
}
