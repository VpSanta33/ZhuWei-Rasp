package com.zhuwei.rasp.core.context;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Carries the request context into {@link java.util.concurrent.ThreadPoolExecutor} tasks.
 *
 * <p>On {@code execute(task)} the submitter's context snapshot is remembered against the task object;
 * on {@code beforeExecute(thread, task)} it is installed on the worker thread and on
 * {@code afterExecute} removed. The task itself is never wrapped or replaced, so executor semantics
 * ({@code remove}, {@code shutdownNow}, {@code Future} identity) are unchanged.</p>
 *
 * <p>Keys are weak and compared by identity: business {@code hashCode/equals} are never called, and
 * tasks that are rejected or never run do not leak.</p>
 *
 * <p>Not covered: ForkJoinPool (parallel streams, CompletableFuture default executor), raw
 * {@code new Thread()}, scheduled executors' delayed tasks, and executors whose subclasses override
 * {@code beforeExecute} without calling super.</p>
 */
public final class AsyncContexts {

    private static final int MAX_ENTRIES = 100_000;

    private static final ConcurrentHashMap<Key, RequestContext> PENDING = new ConcurrentHashMap<>();
    private static final ReferenceQueue<Object> QUEUE = new ReferenceQueue<>();

    private AsyncContexts() { }

    /** Called on execute(): remember the current request (if any) for this task. */
    public static void submit(Object task) {
        RequestContext ctx = ContextHolder.get();
        if (ctx == null || task == null) {
            return;
        }
        expunge();
        if (PENDING.size() >= MAX_ENTRIES) {
            return; // degrade instead of growing without bound
        }
        PENDING.put(new Key(task, QUEUE), ctx.snapshotForAsync());
    }

    /** Called on beforeExecute(): install the task's context on the worker thread. */
    public static void before(Object task) {
        RequestContext cur = ContextHolder.get();
        if (cur != null && cur.async) {
            ContextHolder.clear(); // left over from a task whose afterExecute was not called
        }
        if (task == null) {
            return;
        }
        RequestContext ctx = PENDING.remove(new Lookup(task));
        if (ctx != null && ContextHolder.get() == null) {
            ContextHolder.set(ctx);
        }
    }

    /** Called on afterExecute(): remove the async context, never a real request context. */
    public static void after() {
        RequestContext cur = ContextHolder.get();
        if (cur != null && cur.async) {
            ContextHolder.clear();
        }
    }

    public static int pending() {
        expunge();
        return PENDING.size();
    }

    private static void expunge() {
        Object ref;
        while ((ref = QUEUE.poll()) != null) {
            PENDING.remove(ref);
        }
    }

    /** Weak identity key stored in the map. */
    private static final class Key extends WeakReference<Object> {
        private final int hash;

        Key(Object referent, ReferenceQueue<Object> q) {
            super(referent, q);
            this.hash = System.identityHashCode(referent);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            Object mine = get();
            if (mine == null) {
                return false;
            }
            if (o instanceof Key) {
                return mine == ((Key) o).get();
            }
            return o instanceof Lookup && mine == ((Lookup) o).referent;
        }
    }

    /** Strong, short-lived key used only for lookups. */
    private static final class Lookup {
        private final Object referent;
        private final int hash;

        Lookup(Object referent) {
            this.referent = referent;
            this.hash = System.identityHashCode(referent);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof Key) {
                return ((Key) o).get() == referent;
            }
            return o instanceof Lookup && ((Lookup) o).referent == referent;
        }
    }
}
