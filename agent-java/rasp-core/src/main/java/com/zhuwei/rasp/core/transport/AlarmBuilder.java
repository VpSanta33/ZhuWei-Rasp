package com.zhuwei.rasp.core.transport;

import com.zhuwei.rasp.core.context.RequestContext;
import com.zhuwei.rasp.core.engine.CheckResult;
import com.zhuwei.rasp.core.engine.CheckType;
import com.zhuwei.rasp.core.policy.RuntimeConfig;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** Builds the alarm event described in docs chapter 7.3.5 (with masking of sensitive values). */
public final class AlarmBuilder {

    private static final int MAX_VALUE_LEN = 2048;

    private AlarmBuilder() { }

    public static Map<String, Object> build(CheckType type, Map<String, Object> params, CheckResult r,
                                            RequestContext ctx, RuntimeConfig cfg) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("event_id", UUID.randomUUID().toString());
        e.put("event_time", System.currentTimeMillis());
        e.put("attack_type", type.code);
        e.put("algorithm", r.algorithm);
        e.put("action", r.action.code());
        e.put("confidence", r.confidence);
        e.put("reason", r.reason);
        e.put("matched_input", truncate(r.matchedInput));
        Map<String, Object> p = new LinkedHashMap<>();
        for (Map.Entry<String, Object> kv : params.entrySet()) {
            Object v = kv.getValue();
            p.put(kv.getKey(), v instanceof String ? truncate((String) v) : v);
        }
        e.put("params", p);
        if (ctx != null) {
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("request_id", ctx.requestId);
            req.put("method", ctx.method());
            req.put("url", truncate(ctx.url()));
            req.put("client_ip", ctx.remoteAddr());
            String xff = ctx.header("x-forwarded-for");
            req.put("real_ip", xff.isEmpty() ? ctx.remoteAddr() : xff.split(",")[0].trim());
            Map<String, String> headers = new LinkedHashMap<>();
            for (Map.Entry<String, String> h : ctx.reportHeaders().entrySet()) {
                headers.put(h.getKey(), cfg.maskHeaders.contains(h.getKey()) ? "******" : truncate(h.getValue()));
            }
            req.put("headers", headers);
            Map<String, List<String>> qp = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> kv : ctx.params().entrySet()) {
                boolean mask = cfg.maskParams.contains(kv.getKey().toLowerCase(Locale.ROOT));
                List<String> vs = new ArrayList<>();
                for (String v : kv.getValue()) {
                    vs.add(mask ? "******" : truncate(v));
                }
                qp.put(kv.getKey(), vs);
            }
            req.put("params", qp);
            Map<String, List<String>> bp = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> kv : ctx.bodyParams().entrySet()) {
                if (kv.getKey().equals("$key")) {
                    continue;
                }
                boolean mask = cfg.maskParams.contains(lastSegment(kv.getKey()).toLowerCase(Locale.ROOT));
                List<String> vs = new ArrayList<>();
                for (String v : kv.getValue()) {
                    vs.add(mask ? "******" : truncate(v));
                }
                bp.put(kv.getKey(), vs);
            }
            if (!bp.isEmpty()) {
                req.put("body_params", bp);
            }
            req.put("body_bytes", ctx.bodyLength());
            if (ctx.async) {
                req.put("async", true);
                req.put("thread", Thread.currentThread().getName());
            }
            e.put("request", req);
        }
        e.put("stack", stack(cfg.stackDepth));
        return e;
    }

    static List<String> stack(int depth) {
        StackTraceElement[] st = new Throwable().getStackTrace();
        List<String> out = new ArrayList<>();
        for (StackTraceElement s : st) {
            String c = s.getClassName();
            if (c.startsWith("com.zhuwei.rasp.")) {
                continue;
            }
            out.add(s.toString());
            if (out.size() >= depth) {
                break;
            }
        }
        return out;
    }

    private static String lastSegment(String path) {
        String p = path.endsWith("[]") ? path.substring(0, path.length() - 2) : path;
        int i = p.lastIndexOf('.');
        return i >= 0 ? p.substring(i + 1) : p;
    }

    private static String truncate(String s) {
        if (s == null) {
            return null;
        }
        return s.length() > MAX_VALUE_LEN ? s.substring(0, MAX_VALUE_LEN) + "...(truncated)" : s;
    }
}
