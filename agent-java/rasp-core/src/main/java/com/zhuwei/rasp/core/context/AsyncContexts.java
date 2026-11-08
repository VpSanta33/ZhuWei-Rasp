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
 * <p>The same weak map also serves plain {@code java.lang.Thread}s (keyed by the thread on
 * {@code start()}, installed for the duration of {@code run()}) and ForkJoinTasks (keyed on construction,
 * installed for the duration of {@code doExec()}). Those use {@link #enterTask}/{@link #exitTask}, which
 * keep a per-thread stack because ForkJoin tasks nest (a joining worker runs other tasks inline).</p>
 *
 * <p>Not covered: Thread subclasses that override {@code run()} (and virtual threads), executors whose
 * subclasses override {@code beforeExecute} without calling super, and custom executors that are neither
 * ThreadPoolExecutor nor ForkJoinPool. A long-lived plain thread started during a request (e.g. a lazily
 * started background worker) keeps that request's context for its whole life.</p>
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

    /** Thread.start() / ForkJoinTask constructor. Only plain Thread instances, see class comment. */
    public static void created(Object task) {
        if (task instanceof Thread && task.getClass() != Thread.class) {
            return;
        }
        submit(task);
    }

    private static final Object NONE = new Object();
    private static final ThreadLocal<java.util.ArrayDeque<Object>> STACK =
            ThreadLocal.withInitial(java.util.ArrayDeque::new);
    private static final int MAX_STACK = 1024;

    /** Thread.run() / ForkJoinTask.doExec() entered: push the current context, install the task's one. */
    public static void enterTask(Object task, boolean enabled) {
        java.util.ArrayDeque<Object> st = STACK.get();
        RequestContext cur = ContextHolder.get();
        if (st.size() >= MAX_STACK) {
            st.clear(); // unbalanced somewhere; reset rather than grow
        }
        st.push(cur == null ? NONE : cur);
        if (task == null || PENDING.isEmpty()) {
            return;
        }
        RequestContext ctx = PENDING.remove(new Lookup(task));
        // never replace a real request context (e.g. a request thread helping with a parallel stream)
        if (enabled && ctx != null && (cur == null || cur.async)) {
            ContextHolder.set(ctx);
        }
    }

    /** Matching exit: restore whatever was current before {@link #enterTask}. */
    public static void exitTask() {
        java.util.ArrayDeque<Object> st = STACK.get();
        Object prev = st.poll();
        if (prev == null) {
            return;
        }
        RequestContext cur = ContextHolder.get();
        if (prev == NONE) {
            if (cur != null && cur.async) {
                ContextHolder.clear();
            }
        } else if (prev != cur && (cur == null || cur.async)) {
            ContextHolder.set((RequestContext) prev);
        }
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
