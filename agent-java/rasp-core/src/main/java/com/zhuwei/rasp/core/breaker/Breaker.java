package com.zhuwei.rasp.core.breaker;

import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.RaspLog;

import java.io.File;
import java.util.concurrent.atomic.LongAdder;

/**
 * Self-protection circuit breaker. When the agent costs too much (average check time) or misbehaves
 * (internal errors), all detection is switched off for {@code recover_sec}; heartbeats keep running.
 * Creating the file {@code <home>/DISABLE} switches detection off immediately (manual emergency stop).
 */
public final class Breaker {

    public enum State { CLOSED, OPEN, MANUAL_OFF }

    private static final LongAdder CHECK_NANOS = new LongAdder();
    private static final LongAdder CHECK_COUNT = new LongAdder();
    private static final LongAdder HOOK_COUNT = new LongAdder();
    private static final LongAdder ERRORS = new LongAdder();

    private static volatile State state = State.CLOSED;
    private static volatile long openUntil;
    private static volatile long lastAvgMicros;
    private static volatile long lastHooksPerWindow;
    private static volatile int overloadedWindows;
    private static volatile Thread thread;
    private static volatile boolean running;

    private Breaker() { }

    public static boolean allow() {
        return state == State.CLOSED;
    }

    public static State state() {
        return state;
    }

    public static void recordHook() {
        HOOK_COUNT.increment();
    }

    public static void recordCheck(long nanos) {
        CHECK_NANOS.add(nanos);
        CHECK_COUNT.increment();
    }

    public static void recordError() {
        ERRORS.increment();
    }

    public static long lastAvgMicros() {
        return lastAvgMicros;
    }

    public static long lastHooksPerWindow() {
        return lastHooksPerWindow;
    }

    public static synchronized void start(File home) {
        if (thread != null) {
            return;
        }
        running = true;
        File disable = new File(home, "DISABLE");
        thread = new Thread(() -> loop(disable), "zhuwei-rasp-monitor");
        thread.setDaemon(true);
        thread.start();
    }

    public static synchronized void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
            thread = null;
        }
    }

    private static void loop(File disable) {
        Guard.markAgentThread();
        while (running) {
            RuntimeConfig cfg = ConfigManager.current();
            try {
                Thread.sleep(cfg.breakerWindowSec * 1000L);
            } catch (InterruptedException e) {
                return;
            }
            try {
                evaluate(cfg, disable.exists());
            } catch (Throwable t) {
                RaspLog.warn("breaker evaluation failed", t);
            }
        }
    }

    static void evaluate(RuntimeConfig cfg, boolean manualOff) {
        long nanos = CHECK_NANOS.sumThenReset();
        long count = CHECK_COUNT.sumThenReset();
        long errors = ERRORS.sumThenReset();
        lastHooksPerWindow = HOOK_COUNT.sumThenReset();
        long avg = count == 0 ? 0 : nanos / count / 1000;
        lastAvgMicros = avg;

        if (manualOff) {
            if (state != State.MANUAL_OFF) {
                RaspLog.warn("DISABLE file found, detection switched off");
                state = State.MANUAL_OFF;
            }
            return;
        }
        if (state == State.MANUAL_OFF) {
            RaspLog.info("DISABLE file removed, detection back on");
            state = State.CLOSED;
        }
        long now = System.currentTimeMillis();
        if (state == State.OPEN) {
            if (now >= openUntil) {
                RaspLog.info("breaker recovered, detection back on");
                state = State.CLOSED;
                overloadedWindows = 0;
            }
            return;
        }
        boolean overloaded = (count >= 100 && avg > cfg.breakerAvgCheckMicros) || errors > cfg.breakerErrorsPerWindow;
        overloadedWindows = overloaded ? overloadedWindows + 1 : 0;
        if (overloadedWindows >= 3) {
            state = State.OPEN;
            openUntil = now + cfg.breakerRecoverSec * 1000L;
            RaspLog.warn("breaker OPEN: avg_check_us=" + avg + " errors=" + errors
                    + ", detection off for " + cfg.breakerRecoverSec + "s");
        }
    }
}
