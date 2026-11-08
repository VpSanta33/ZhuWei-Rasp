package com.zhuwei.rasp.bootstrap;

/**
 * Implemented in rasp-core and installed into {@link Spy}.
 * The interface lives in the bootstrap jar so instrumented JDK classes can see it.
 */
public interface SpyHandler {

    /** Called on method entry. Return a Throwable to make the instrumented method throw it (block). */
    Throwable onEnter(int hookId, Object self, Object[] args);

    /** Called on normal return of a hooked method (only for hooks that request exit callbacks). */
    void onReturn(int hookId, Object self, Object[] args);

    /**
     * Called when a hooked method (that requests exit callbacks) throws.
     * Return true to swallow the exception (only honoured for void methods, e.g. a request entry
     * that has already written the block page).
     */
    boolean onThrow(int hookId, Object self, Object[] args, Throwable t);

    /**
     * Called on normal return with the (boxed) return value, for hooks that need it
     * (e.g. ServletInputStream.read returning the byte count). {@code args} is the array captured on entry.
     * Default method so that cores built against an older bootstrap keep working.
     */
    default void onReturnValue(Object ret, int hookId, Object self, Object[] args) { }

    SpyHandler NOP = new SpyHandler() {
        public Throwable onEnter(int hookId, Object self, Object[] args) { return null; }
        public void onReturn(int hookId, Object self, Object[] args) { }
        public boolean onThrow(int hookId, Object self, Object[] args, Throwable t) { return false; }
    };
}
