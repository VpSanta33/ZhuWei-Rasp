package com.zhuwei.rasp.launcher;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * Isolated loader for rasp-core. Parent is the platform loader (the extension loader on JDK 8), so business classes
 * (and their versions of common libraries) are never visible to the agent, and vice versa.
 * Bootstrap classes (including Spy) are still reachable through the parent chain.
 */
final class RaspClassLoader extends URLClassLoader {

    static {
        ClassLoader.registerAsParallelCapable();
    }

    RaspClassLoader(URL[] urls) {
        super(urls, platformLoader());
    }

    /** ClassLoader.getPlatformClassLoader() is JDK 9+; on JDK 8 the extension loader plays that role. */
    private static ClassLoader platformLoader() {
        try {
            return (ClassLoader) ClassLoader.class.getMethod("getPlatformClassLoader").invoke(null);
        } catch (Exception e) {
            return ClassLoader.getSystemClassLoader().getParent();
        }
    }

    @Override
    public String toString() {
        return "RaspClassLoader";
    }
}
