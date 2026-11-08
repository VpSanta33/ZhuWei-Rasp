package com.zhuwei.rasp.bootstrap;

/**
 * The only class that instrumented code calls. Every method swallows its own failures so that
 * the agent can never break the business code (except for intentional blocking).
 */
public final class Spy {

    private static volatile SpyHandler handler = SpyHandler.NOP;

    private Spy() { }

    public static void install(SpyHandler h) {
        handler = h == null ? SpyHandler.NOP : h;
    }

    public static void uninstall() {
        handler = SpyHandler.NOP;
    }

    public static boolean isInstalled() {
        return handler != SpyHandler.NOP;
    }

    public static Throwable onEnter(int hookId, Object self, Object[] args) {
        try {
            return handler.onEnter(hookId, self, args);
        } catch (Throwable t) {
            return null;
        }
    }

    public static void onReturn(int hookId, Object self, Object[] args) {
        try {
            handler.onReturn(hookId, self, args);
        } catch (Throwable ignore) {
            // never affect business code
        }
    }

    /** Return value first so the woven code needs no stack shuffling: [ret] DUP, box, push id/self/args, call. */
    public static void onReturnValue(Object ret, int hookId, Object self, Object[] args) {
        try {
            handler.onReturnValue(ret, hookId, self, args);
        } catch (Throwable ignore) {
            // never affect business code
        }
    }

    public static boolean onThrow(int hookId, Object self, Object[] args, Throwable t) {
        try {
            return handler.onThrow(hookId, self, args, t);
        } catch (Throwable ignore) {
            return false;
        }
    }
}
