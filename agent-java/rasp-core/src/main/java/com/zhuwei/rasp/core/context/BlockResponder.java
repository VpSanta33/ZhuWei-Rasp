package com.zhuwei.rasp.core.context;

import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.util.RaspLog;
import com.zhuwei.rasp.core.util.Reflect;

import java.io.OutputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

/** Writes the configured block page to the servlet response, if it has not been committed yet. */
public final class BlockResponder {

    private BlockResponder() { }

    public static boolean write(RequestContext ctx, RuntimeConfig cfg) {
        if (ctx.blockPageWritten) {
            return true;
        }
        Object resp = ctx.response;
        Object committed = Reflect.call(resp, "isCommitted");
        if (Boolean.TRUE.equals(committed)) {
            RaspLog.warn("response already committed, cannot write block page for " + ctx.requestId);
            return false;
        }
        try {
            Reflect.call(resp, "reset");
            boolean json = ctx.header("accept").contains("application/json")
                    || ctx.header("content-type").contains("application/json");
            String body = (json ? cfg.blockJson : cfg.blockHtml).replace("%request_id%", ctx.requestId);
            Reflect.call(resp, "setStatus", new Class<?>[]{int.class}, cfg.blockStatus);
            Reflect.call(resp, "setContentType", new Class<?>[]{String.class},
                    json ? "application/json;charset=UTF-8" : "text/html;charset=UTF-8");
            Object w = Reflect.call(resp, "getWriter");
            if (w instanceof Writer) {
                ((Writer) w).write(body);
                ((Writer) w).flush();
            } else {
                Object os = Reflect.call(resp, "getOutputStream");
                if (!(os instanceof OutputStream)) {
                    return false;
                }
                ((OutputStream) os).write(body.getBytes(StandardCharsets.UTF_8));
                ((OutputStream) os).flush();
            }
            ctx.blockPageWritten = true;
            return true;
        } catch (Throwable t) {
            RaspLog.warn("write block page failed", t);
            return false;
        }
    }
}
