package com.zhuwei.rasp.core.util;

/**
 * Re-entrance guard. While the agent itself runs (checking, reporting, logging, transforming)
 * any hook it triggers must be ignored, otherwise we get recursion and false alarms.
 */
public final class Guard {

    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);

    private Guard() { }

    /** @return true if the caller acquired the guard and must call {@link #exit()} */
    public static boolean enter() {
        int[] d = DEPTH.get();
        if (d[0] > 0) {
            return false;
        }
        d[0] = 1;
        return true;
    }

    public static void exit() {
        DEPTH.get()[0] = 0;
    }

    public static boolean inRasp() {
        return DEPTH.get()[0] > 0;
    }

    /** Permanently mark the current (agent-owned) thread. */
    public static void markAgentThread() {
        DEPTH.get()[0] = 1;
    }
}
