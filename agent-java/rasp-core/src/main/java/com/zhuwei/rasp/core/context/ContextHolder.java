package com.zhuwei.rasp.core.context;

/** ThreadLocal holder. Always cleared by the outermost request-entry hook (see RaspSpyHandler). */
public final class ContextHolder {

    private static final ThreadLocal<RequestContext> CURRENT = new ThreadLocal<>();

    private ContextHolder() { }

    public static RequestContext get() {
        return CURRENT.get();
    }

    public static void set(RequestContext ctx) {
        CURRENT.set(ctx);
    }

    public static void clear() {
        CURRENT.remove();
    }
}
