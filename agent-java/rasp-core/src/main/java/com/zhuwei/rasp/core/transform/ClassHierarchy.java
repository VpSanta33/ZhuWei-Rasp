package com.zhuwei.rasp.core.transform;

import com.zhuwei.rasp.core.util.Guard;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves super types by reading class bytes as resources, never by loading classes.
 * Loading business classes from inside a transformer can deadlock or trigger static initialisers.
 */
public final class ClassHierarchy {

    static final class Info {
        final String superName;
        final String[] interfaces;
        final boolean isInterface;

        Info(String superName, String[] interfaces, boolean isInterface) {
            this.superName = superName;
            this.interfaces = interfaces;
            this.isInterface = isInterface;
        }
    }

    private static final Info UNKNOWN = new Info(null, new String[0], false);
    private static final Object BOOT = new Object();

    /** loader -> (internal name -> info). Weak keys so business class loaders can be collected. */
    private final Map<Object, Map<String, Info>> cache = Collections.synchronizedMap(new WeakHashMap<>());

    public void remember(ClassLoader loader, ClassReader cr) {
        map(loader).put(cr.getClassName(),
                new Info(cr.getSuperName(), cr.getInterfaces(), (cr.getAccess() & Opcodes.ACC_INTERFACE) != 0));
    }

    /** @return true if {@code name} is, extends or implements {@code target} (all internal names). */
    public boolean isSubtypeOf(ClassLoader loader, String name, String target) {
        return isSubtypeOf(loader, name, target, new HashSet<>(), 0);
    }

    private boolean isSubtypeOf(ClassLoader loader, String name, String target, Set<String> seen, int depth) {
        if (name == null || depth > 32 || !seen.add(name)) {
            return false;
        }
        if (name.equals(target)) {
            return true;
        }
        if (name.equals("java/lang/Object")) {
            return false;
        }
        Info info = info(loader, name);
        for (String i : info.interfaces) {
            if (isSubtypeOf(loader, i, target, seen, depth + 1)) {
                return true;
            }
        }
        return isSubtypeOf(loader, info.superName, target, seen, depth + 1);
    }

    /** Common super class for ASM frame computation. Falls back to java/lang/Object. */
    public String commonSuperClass(ClassLoader loader, String a, String b) {
        if (isSubtypeOf(loader, b, a)) {
            return info(loader, a).isInterface ? "java/lang/Object" : a;
        }
        if (isSubtypeOf(loader, a, b)) {
            return info(loader, b).isInterface ? "java/lang/Object" : b;
        }
        Info ia = info(loader, a);
        if (ia.isInterface || info(loader, b).isInterface) {
            return "java/lang/Object";
        }
        String cur = ia.superName;
        int guard = 0;
        while (cur != null && guard++ < 64) {
            if (isSubtypeOf(loader, b, cur)) {
                return cur;
            }
            cur = info(loader, cur).superName;
        }
        return "java/lang/Object";
    }

    Info info(ClassLoader loader, String name) {
        Map<String, Info> m = map(loader);
        Info i = m.get(name);
        if (i != null) {
            return i;
        }
        i = read(loader, name);
        if (i == UNKNOWN && loader != null) {
            // types like java/sql/Statement live in a parent loader
            Info parent = read(null, name);
            if (parent != UNKNOWN) {
                i = parent;
            }
        }
        m.put(name, i);
        return i;
    }

    private Map<String, Info> map(ClassLoader loader) {
        Object key = loader == null ? BOOT : loader;
        return cache.computeIfAbsent(key, k -> new ConcurrentHashMap<>());
    }

    private static Info read(ClassLoader loader, String name) {
        boolean acquired = Guard.enter();
        String res = name + ".class";
        try (InputStream in = loader == null ? ClassLoader.getSystemResourceAsStream(res) : loader.getResourceAsStream(res)) {
            InputStream src = in;
            if (src == null && loader == null) {
                // platform/boot module classes
                src = com.zhuwei.rasp.core.util.Jdk.platformClassLoader().getResourceAsStream(res);
            }
            if (src == null) {
                return UNKNOWN;
            }
            try (InputStream s = src) {
                ByteArrayOutputStream bo = new ByteArrayOutputStream(4096);
                byte[] buf = new byte[4096];
                int n;
                while ((n = s.read(buf)) > 0) {
                    bo.write(buf, 0, n);
                }
                ClassReader cr = new ClassReader(bo.toByteArray());
                return new Info(cr.getSuperName(), cr.getInterfaces(), (cr.getAccess() & Opcodes.ACC_INTERFACE) != 0);
            }
        } catch (Throwable t) {
            return UNKNOWN;
        } finally {
            if (acquired) {
                Guard.exit();
            }
        }
    }
}
