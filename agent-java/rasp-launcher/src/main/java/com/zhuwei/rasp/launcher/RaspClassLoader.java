package com.zhuwei.rasp.launcher;

import java.net.URL;
import java.net.URLClassLoader;

/**
 * Isolated loader for rasp-core. Parent is the platform loader, so business classes
 * (and their versions of common libraries) are never visible to the agent, and vice versa.
 * Bootstrap classes (including Spy) are still reachable through the parent chain.
 */
final class RaspClassLoader extends URLClassLoader {

    static {
        ClassLoader.registerAsParallelCapable();
    }

    RaspClassLoader(URL[] urls) {
        super("zhuwei-rasp", urls, ClassLoader.getPlatformClassLoader());
    }

    @Override
    public String toString() {
        return "RaspClassLoader";
    }
}
