package com.zhuwei.rasp.core.hook;

import com.zhuwei.rasp.core.engine.CheckType;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Declarative description of one instrumentation point.
 * A class matches either by exact internal name ({@link #className}) or by being a subtype of
 * {@link #iface} (interface or super class, matched through the whole type hierarchy).
 */
public final class HookPoint {

    public enum Kind {
        /** Servlet service(): creates / clears the request context. */
        REQUEST_ENTRY,
        /** Dangerous operation to check. */
        SINK,
        /** ServletInputStream read: passively copies the request body the application reads. */
        BODY_READ,
        /** ThreadPoolExecutor.execute: remember the submitter's request context for the task. */
        ASYNC_SUBMIT,
        /** ThreadPoolExecutor.beforeExecute: install the task's context on the worker thread. */
        ASYNC_BEFORE,
        /** ThreadPoolExecutor.afterExecute: remove it again. */
        ASYNC_AFTER,
        /** Thread.start / ForkJoinTask constructor: remember the creator's request context for {@code self}. */
        TASK_CREATE,
        /** Thread.run / ForkJoinTask.doExec: install the context for the duration of the call (exit restores). */
        TASK_RUN
    }

    /** Converts the raw hooked call into named check parameters. */
    public interface ParamExtractor {
        Map<String, Object> extract(Object self, Object[] args) throws Exception;
    }

    public final int id;
    public final String name;
    public final Kind kind;
    public final CheckType type;
    public final String className;
    public final String iface;
    public final Set<String> methods;
    /** Exact descriptor, or a prefix when it ends with '*'. */
    public final String desc;
    /** try/catch around the body with onReturn/onThrow callbacks (void methods may swallow). */
    public final boolean exitCallbacks;
    /** onReturnValue callback with the boxed return value and the entry-time argument array. */
    public final boolean returnValue;
    public final ParamExtractor extractor;

    HookPoint(int id, String name, Kind kind, CheckType type, String className, String iface,
              String[] methods, String desc, boolean exitCallbacks, boolean returnValue, ParamExtractor extractor) {
        this.id = id;
        this.name = name;
        this.kind = kind;
        this.type = type;
        this.className = className;
        this.iface = iface;
        this.methods = new HashSet<>(Arrays.asList(methods));
        this.desc = desc;
        this.exitCallbacks = exitCallbacks;
        this.returnValue = returnValue;
        this.extractor = extractor;
    }

    public boolean matchesMethod(String methodName, String methodDesc) {
        if (!methods.contains(methodName)) {
            return false;
        }
        if (desc.endsWith("*")) {
            return methodDesc.startsWith(desc.substring(0, desc.length() - 1));
        }
        return desc.equals(methodDesc);
    }

    @Override
    public String toString() {
        return name + "#" + id;
    }
}
