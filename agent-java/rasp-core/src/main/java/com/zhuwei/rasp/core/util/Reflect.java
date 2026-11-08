package com.zhuwei.rasp.core.util;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reflection helpers for calling methods on business objects (servlet request/response) that
 * the agent cannot reference at compile time. Methods are resolved on a public declaring type
 * (usually the servlet interface) so the call works even when the implementation class is not public.
 */
public final class Reflect {

    private static final Method MISSING;
    private static final Map<String, Method> CACHE = new ConcurrentHashMap<>();

    static {
        try {
            MISSING = Object.class.getMethod("hashCode");
        } catch (NoSuchMethodException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private Reflect() { }

    public static Object call(Object target, String name) {
        return call(target, name, new Class<?>[0]);
    }

    public static Object call(Object target, String name, Class<?>[] types, Object... args) {
        if (target == null) {
            return null;
        }
        Method m = find(target.getClass(), name, types);
        if (m == null) {
            return null;
        }
        try {
            return m.invoke(target, args);
        } catch (Throwable t) {
            if (RaspLog.isDebug()) {
                RaspLog.debug("reflect call " + name + " failed: " + t);
            }
            return null;
        }
    }

    public static boolean has(Object target, String name, Class<?>... types) {
        return target != null && find(target.getClass(), name, types) != null;
    }

    private static Method find(Class<?> cls, String name, Class<?>[] types) {
        StringBuilder key = new StringBuilder(cls.getName()).append('#').append(name);
        for (Class<?> t : types) {
            key.append(',').append(t.getName());
        }
        Method m = CACHE.computeIfAbsent(key.toString(), k -> {
            Method r = resolve(cls, name, types);
            return r == null ? MISSING : r;
        });
        return m == MISSING ? null : m;
    }

    private static Method resolve(Class<?> cls, String name, Class<?>[] types) {
        Deque<Class<?>> todo = new ArrayDeque<>();
        Set<Class<?>> seen = new HashSet<>();
        todo.add(cls);
        while (!todo.isEmpty()) {
            Class<?> c = todo.poll();
            if (!seen.add(c)) {
                continue;
            }
            if (Modifier.isPublic(c.getModifiers()) && isExported(c)) {
                try {
                    Method m = c.getMethod(name, types);
                    if (Modifier.isPublic(m.getDeclaringClass().getModifiers())) {
                        return m;
                    }
                } catch (NoSuchMethodException ignore) {
                    // keep searching
                }
            }
            for (Class<?> i : c.getInterfaces()) {
                todo.add(i);
            }
            if (c.getSuperclass() != null) {
                todo.add(c.getSuperclass());
            }
        }
        return null;
    }

    private static boolean isExported(Class<?> c) {
        Module m = c.getModule();
        return !m.isNamed() || m.isExported(c.getPackageName());
    }
}
