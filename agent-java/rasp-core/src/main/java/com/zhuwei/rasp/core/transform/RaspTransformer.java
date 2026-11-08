package com.zhuwei.rasp.core.transform;

import com.zhuwei.rasp.core.hook.HookPoint;
import com.zhuwei.rasp.core.hook.HookRegistry;
import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.RaspLog;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Matches classes against {@link HookRegistry} and rewrites the matched methods.
 * Never throws: on any failure the original bytes are kept (return null).
 */
public final class RaspTransformer implements ClassFileTransformer {

    private static final String[] SKIP_PREFIXES = {
            "com/zhuwei/rasp/", "java/lang/invoke/", "jdk/internal/", "sun/invoke/", "java/lang/ref/",
    };

    private static final ThreadLocal<boolean[]> IN_TRANSFORM = ThreadLocal.withInitial(() -> new boolean[1]);

    private final Instrumentation inst;
    private final ClassHierarchy hierarchy = new ClassHierarchy();
    private final Module spyModule;
    private final ClassLoader raspLoader = RaspTransformer.class.getClassLoader();
    /** Names of classes we have instrumented, used for uninstall and diagnostics. */
    private final Set<String> transformed = ConcurrentHashMap.newKeySet();
    private final Map<String, Boolean> exactNames = new ConcurrentHashMap<>();
    private final File dumpDir;
    private volatile boolean enabled = true;

    public RaspTransformer(Instrumentation inst, Module spyModule, File dumpDir) {
        this.inst = inst;
        this.spyModule = spyModule;
        this.dumpDir = dumpDir;
        this.spySupportsReturnValue = spyHasMethod("onReturnValue");
        if (!spySupportsReturnValue) {
            RaspLog.warn("bootstrap Spy is an older version (loaded by a previous attach); "
                    + "hooks needing return values are disabled until the JVM restarts");
        }
        for (HookPoint h : HookRegistry.all()) {
            if (h.className != null) {
                exactNames.put(h.className, Boolean.TRUE);
            }
        }
    }

    private final boolean spySupportsReturnValue;

    /** Spy lives in the bootstrap loader and survives detach; a newer core must not call methods it lacks. */
    private static boolean spyHasMethod(String name) {
        for (java.lang.reflect.Method m : com.zhuwei.rasp.bootstrap.Spy.class.getMethods()) {
            if (m.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private boolean usable(HookPoint h) {
        return !h.returnValue || spySupportsReturnValue;
    }

    public void disable() {
        enabled = false;
    }

    public Set<String> transformedClasses() {
        return Collections.unmodifiableSet(transformed);
    }

    @Override
    public byte[] transform(Module module, ClassLoader loader, String className, Class<?> redefined,
                            ProtectionDomain pd, byte[] bytes) {
        if (!enabled || className == null || loader == raspLoader) {
            return null;
        }
        // Own re-entrance flag: Guard may legitimately be held by the agent thread doing retransformation.
        boolean[] busy = IN_TRANSFORM.get();
        if (busy[0]) {
            return null;
        }
        busy[0] = true;
        boolean acquired = Guard.enter();
        try {
            for (String p : SKIP_PREFIXES) {
                if (className.startsWith(p)) {
                    return null;
                }
            }
            ClassReader cr = new ClassReader(bytes);
            List<HookPoint> hooks = match(loader, cr);
            if (hooks.isEmpty()) {
                return null;
            }
            ensureReadsSpy(module);
            ClassWriter cw = new SafeClassWriter(cr, hierarchy, loader);
            boolean[] changed = {false};
            ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] ex) {
                    MethodVisitor mv = super.visitMethod(access, name, desc, sig, ex);
                    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) {
                        return mv;
                    }
                    for (HookPoint h : hooks) {
                        if (h.matchesMethod(name, desc)) {
                            changed[0] = true;
                            return new HookMethodAdapter(mv, access, name, desc, h);
                        }
                    }
                    return mv;
                }
            };
            cr.accept(cv, ClassReader.EXPAND_FRAMES);
            if (!changed[0]) {
                return null;
            }
            byte[] out = cw.toByteArray();
            transformed.add(className.replace('/', '.'));
            RaspLog.info("instrumented " + className + " hooks=" + hooks);
            dump(className, out);
            return out;
        } catch (Throwable t) {
            RaspLog.warn("transform failed for " + className + ", keeping original", t);
            return null;
        } finally {
            busy[0] = false;
            if (acquired) {
                Guard.exit();
            }
        }
    }

    private List<HookPoint> match(ClassLoader loader, ClassReader cr) {
        String name = cr.getClassName();
        boolean isInterface = (cr.getAccess() & Opcodes.ACC_INTERFACE) != 0;
        List<HookPoint> result = new ArrayList<>(2);
        if (exactNames.containsKey(name)) {
            for (HookPoint h : HookRegistry.all()) {
                if (name.equals(h.className) && usable(h)) {
                    result.add(h);
                }
            }
            return result;
        }
        if (isInterface || loader == null || name.startsWith("java/") || name.startsWith("javax/")
                || name.startsWith("sun/") || name.startsWith("jdk/")) {
            return result;
        }
        String[] ifaces = cr.getInterfaces();
        if (ifaces.length == 0 && "java/lang/Object".equals(cr.getSuperName())) {
            return result; // fast path for most classes
        }
        hierarchy.remember(loader, cr);
        for (HookPoint h : HookRegistry.all()) {
            if (h.iface != null && usable(h) && hierarchy.isSubtypeOf(loader, name, h.iface)) {
                result.add(h);
            }
        }
        return result;
    }

    /** Whether an already-loaded class should be retransformed at startup (attach or early-loaded JDK classes). */
    public boolean shouldRetransform(Class<?> c) {
        if (!inst.isModifiableClass(c) || c.isInterface() || c.isArray() || c.isPrimitive()) {
            return false;
        }
        String internal = c.getName().replace('.', '/');
        if (exactNames.containsKey(internal)) {
            return true;
        }
        if (c.getClassLoader() == null || c.getClassLoader() == raspLoader) {
            return false;
        }
        for (HookPoint h : HookRegistry.all()) {
            if (h.iface != null && usable(h) && implementsByName(c, h.iface.replace('/', '.'))) {
                return true;
            }
        }
        return false;
    }

    /** true if {@code c} has a super class or (super) interface named {@code iface}. */
    private static boolean implementsByName(Class<?> c, String iface) {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            if (k != c && k.getName().equals(iface)) {
                return true;
            }
            for (Class<?> i : k.getInterfaces()) {
                if (i.getName().equals(iface) || implementsByName(i, iface)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Named modules (e.g. java.base) must be allowed to read the bootstrap unnamed module holding Spy. */
    private void ensureReadsSpy(Module module) {
        if (module != null && module.isNamed() && !module.canRead(spyModule)) {
            inst.redefineModule(module, Collections.singleton(spyModule), Collections.emptyMap(),
                    Collections.emptyMap(), Collections.emptySet(), Collections.emptyMap());
        }
    }

    private void dump(String className, byte[] out) {
        if (dumpDir == null) {
            return;
        }
        try {
            File f = new File(dumpDir, className + ".class");
            f.getParentFile().mkdirs();
            try (FileOutputStream fo = new FileOutputStream(f)) {
                fo.write(out);
            }
        } catch (Throwable ignore) {
            // debug only
        }
    }

    /** ClassWriter that never loads classes to compute frames. */
    static final class SafeClassWriter extends ClassWriter {
        private final ClassHierarchy hierarchy;
        private final ClassLoader loader;

        SafeClassWriter(ClassReader cr, ClassHierarchy hierarchy, ClassLoader loader) {
            super(cr, COMPUTE_FRAMES | COMPUTE_MAXS);
            this.hierarchy = hierarchy;
            this.loader = loader;
        }

        @Override
        protected String getCommonSuperClass(String a, String b) {
            return hierarchy.commonSuperClass(loader, a, b);
        }
    }
}
