package com.zhuwei.rasp.core.hook;

import com.zhuwei.rasp.bootstrap.RaspBlockException;
import com.zhuwei.rasp.bootstrap.SpyHandler;
import com.zhuwei.rasp.core.breaker.Breaker;
import com.zhuwei.rasp.core.context.AsyncContexts;
import com.zhuwei.rasp.core.context.BlockResponder;
import com.zhuwei.rasp.core.context.ContextHolder;
import com.zhuwei.rasp.core.context.RequestContext;
import com.zhuwei.rasp.core.engine.Action;
import com.zhuwei.rasp.core.engine.CheckResult;
import com.zhuwei.rasp.core.engine.CheckType;
import com.zhuwei.rasp.core.engine.DetectEngine;
import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.transport.AlarmBuilder;
import com.zhuwei.rasp.core.transport.Reporter;
import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.RaspLog;

import java.util.Map;

/** Dispatches Spy callbacks: request lifecycle for entry hooks, detection for sink hooks. */
public final class RaspSpyHandler implements SpyHandler {

    private static final int MAX_CHECKS_PER_REQUEST = 10_000;

    /** Last SQL string checked on this thread: JDBC wrappers/pools delegate, avoid checking twice. */
    private static final ThreadLocal<Object> LAST_SQL = new ThreadLocal<>();

    private final Reporter reporter;

    public RaspSpyHandler(Reporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public Throwable onEnter(int hookId, Object self, Object[] args) {
        HookPoint h = HookRegistry.get(hookId);
        if (h == null || !Guard.enter()) {
            return null;
        }
        try {
            Breaker.recordHook();
            switch (h.kind) {
                case REQUEST_ENTRY:
                    requestEnter(args);
                    return null;
                case SINK:
                    return sink(h, self, args);
                case ASYNC_SUBMIT:
                    if (Breaker.allow() && ConfigManager.current().asyncContext) {
                        AsyncContexts.submit(args[0]);
                    }
                    return null;
                case ASYNC_BEFORE:
                    AsyncContexts.before(args[1]);
                    return null;
                case ASYNC_AFTER:
                    AsyncContexts.after();
                    return null;
                case TASK_CREATE:
                    if (Breaker.allow() && ConfigManager.current().asyncContext) {
                        AsyncContexts.created(self);
                    }
                    return null;
                case TASK_RUN:
                    // always enter/exit in pairs, whatever the breaker/config says, to keep the stack balanced
                    AsyncContexts.enterTask(self, ConfigManager.current().asyncContext);
                    return null;
                default:
                    return null; // BODY_READ acts on return
            }
        } catch (Throwable t) {
            Breaker.recordError();
            if (RaspLog.isDebug()) {
                RaspLog.debug("hook " + h + " error: " + t);
            }
            return null;
        } finally {
            Guard.exit();
        }
    }

    /** ServletInputStream.read(byte[], int, int) / readLine returned: copy what the application just read. */
    @Override
    public void onReturnValue(Object ret, int hookId, Object self, Object[] args) {
        HookPoint h = HookRegistry.get(hookId);
        if (h == null || h.kind != HookPoint.Kind.BODY_READ || !(ret instanceof Integer) || !Guard.enter()) {
            return;
        }
        try {
            int n = (Integer) ret;
            RequestContext ctx = ContextHolder.get();
            if (n > 0 && ctx != null && !ctx.async && args.length == 3 && args[0] instanceof byte[]) {
                ctx.appendBody(self, (byte[]) args[0], (Integer) args[1], n);
            }
        } catch (Throwable t) {
            Breaker.recordError();
        } finally {
            Guard.exit();
        }
    }

    @Override
    public void onReturn(int hookId, Object self, Object[] args) {
        HookPoint h = HookRegistry.get(hookId);
        if (h != null && h.kind == HookPoint.Kind.TASK_RUN) {
            taskExit();
            return;
        }
        if (h == null || h.kind != HookPoint.Kind.REQUEST_ENTRY || !Guard.enter()) {
            return;
        }
        try {
            RequestContext ctx = ContextHolder.get();
            if (ctx == null) {
                return;
            }
            if (--ctx.depth <= 0) {
                if (ctx.blocked && !ctx.blockPageWritten) {
                    // the application caught our exception; still make sure the client gets the block page
                    BlockResponder.write(ctx, ConfigManager.current());
                }
                clear();
            }
        } catch (Throwable t) {
            Breaker.recordError();
            clear();
        } finally {
            Guard.exit();
        }
    }

    private static void taskExit() {
        if (!Guard.enter()) {
            return;
        }
        try {
            AsyncContexts.exitTask();
        } catch (Throwable t) {
            Breaker.recordError();
        } finally {
            Guard.exit();
        }
    }

    @Override
    public boolean onThrow(int hookId, Object self, Object[] args, Throwable t) {
        HookPoint h = HookRegistry.get(hookId);
        if (h != null && h.kind == HookPoint.Kind.TASK_RUN) {
            taskExit();
            return false;
        }
        if (h == null || h.kind != HookPoint.Kind.REQUEST_ENTRY || !Guard.enter()) {
            return false;
        }
        try {
            RequestContext ctx = ContextHolder.get();
            if (ctx == null) {
                return false;
            }
            if (--ctx.depth > 0) {
                return false; // let the outermost service() handle it
            }
            boolean swallow = false;
            if (ctx.blocked && isBlock(t)) {
                swallow = BlockResponder.write(ctx, ConfigManager.current());
            }
            clear();
            return swallow;
        } catch (Throwable e) {
            Breaker.recordError();
            clear();
            return false;
        } finally {
            Guard.exit();
        }
    }

    private void requestEnter(Object[] args) {
        RequestContext ctx = ContextHolder.get();
        if (ctx != null && !ctx.async) {
            ctx.depth++;
            return;
        }
        RuntimeConfig cfg = ConfigManager.current();
        ctx = new RequestContext(args[0], args[1], cfg.readFormParams, cfg.bodyMaxBytes);
        ctx.depth = 1;
        ContextHolder.set(ctx);
        LAST_SQL.remove();
    }

    private Throwable sink(HookPoint h, Object self, Object[] args) throws Exception {
        if (!Breaker.allow()) {
            return null;
        }
        RuntimeConfig cfg = ConfigManager.current();
        CheckType type = h.type;
        if (!cfg.enabled(type)) {
            return null;
        }
        RequestContext ctx = ContextHolder.get();
        if (ctx != null && ++ctx.checkCount > MAX_CHECKS_PER_REQUEST) {
            return null;
        }
        Map<String, Object> params = h.extractor.extract(self, args);
        if (params == null) {
            return null;
        }
        if (type == CheckType.SQL) {
            Object q = params.get("query");
            if (q == LAST_SQL.get()) {
                return null;
            }
            LAST_SQL.set(q);
        }
        long t0 = System.nanoTime();
        CheckResult r = DetectEngine.check(type, params, ctx);
        Breaker.recordCheck(System.nanoTime() - t0);
        if (r.action == Action.PASS) {
            return null;
        }
        reporter.offer(AlarmBuilder.build(type, params, r, ctx, cfg));
        if (r.action != Action.BLOCK) {
            return null;
        }
        String rid = ctx == null ? "" : ctx.requestId;
        if (ctx != null) {
            ctx.blocked = true;
            ctx.blockType = type.code;
        }
        RaspLog.info("BLOCK " + type.code + " by " + r.algorithm + " request_id=" + rid);
        return new RaspBlockException("[ZhuWei-RASP] " + type.code + " blocked: " + r.reason, type.code, rid);
    }

    private static boolean isBlock(Throwable t) {
        for (int i = 0; t != null && i < 16; i++, t = t.getCause()) {
            if (t instanceof RaspBlockException) {
                return true;
            }
        }
        return false;
    }

    private static void clear() {
        ContextHolder.clear();
        LAST_SQL.remove();
    }
}
