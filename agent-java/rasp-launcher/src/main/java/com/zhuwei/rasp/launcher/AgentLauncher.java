package com.zhuwei.rasp.launcher;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.jar.JarFile;

/**
 * Agent entry point for both {@code -javaagent} (premain) and dynamic attach (agentmain).
 *
 * <pre>
 * BootstrapClassLoader  <- rasp-bootstrap.jar (Spy, SpyHandler, RaspBlockException)
 * RaspClassLoader       <- rasp-core.jar      (all logic, isolated from business classes)
 * </pre>
 *
 * Any failure here is printed and swallowed: the business application must always start.
 */
public final class AgentLauncher {

    private static final String LOADED_FLAG = "zhuwei.rasp.loaded";
    private static final String CORE_ENTRY = "com.zhuwei.rasp.core.CoreEngine";

    private static volatile ClassLoader coreLoader;

    private AgentLauncher() { }

    public static void premain(String args, Instrumentation inst) {
        launch(args, inst, false);
    }

    public static void agentmain(String args, Instrumentation inst) {
        if (args != null && args.trim().equals("uninstall")) {
            uninstall();
            return;
        }
        launch(args, inst, true);
    }

    private static synchronized void launch(String args, Instrumentation inst, boolean attach) {
        if (System.getProperty(LOADED_FLAG) != null) {
            log("already loaded, skip");
            return;
        }
        try {
            File home = locateHome();
            File bootstrapJar = new File(home, "rasp-bootstrap.jar");
            File coreJar = new File(home, "rasp-core.jar");
            if (!bootstrapJar.isFile() || !coreJar.isFile()) {
                log("missing rasp-bootstrap.jar or rasp-core.jar in " + home + ", RASP disabled");
                return;
            }
            inst.appendToBootstrapClassLoaderSearch(new JarFile(bootstrapJar));

            RaspClassLoader loader = new RaspClassLoader(new URL[]{coreJar.toURI().toURL()});
            Class<?> entry = loader.loadClass(CORE_ENTRY);
            Method start = entry.getMethod("start", Instrumentation.class, String.class, String.class, boolean.class);
            start.invoke(null, inst, args, home.getAbsolutePath(), attach);
            coreLoader = loader;
            System.setProperty(LOADED_FLAG, "true");
        } catch (Throwable t) {
            log("failed to start, RASP disabled: " + t);
            t.printStackTrace();
        }
    }

    private static synchronized void uninstall() {
        ClassLoader loader = coreLoader;
        if (loader == null) {
            log("not loaded");
            return;
        }
        try {
            loader.loadClass(CORE_ENTRY).getMethod("stop").invoke(null);
            if (loader instanceof RaspClassLoader) {
                ((RaspClassLoader) loader).close();
            }
        } catch (Throwable t) {
            log("uninstall failed: " + t);
        } finally {
            coreLoader = null;
            System.clearProperty(LOADED_FLAG);
        }
    }

    private static File locateHome() throws Exception {
        String override = System.getProperty("rasp.home");
        if (override == null) {
            override = System.getenv("RASP_HOME");
        }
        if (override != null && !override.isEmpty()) {
            return new File(override);
        }
        URL self = AgentLauncher.class.getProtectionDomain().getCodeSource().getLocation();
        return new File(self.toURI()).getParentFile();
    }

    static void log(String msg) {
        System.err.println("[ZhuWei-RASP] " + msg);
    }
}
