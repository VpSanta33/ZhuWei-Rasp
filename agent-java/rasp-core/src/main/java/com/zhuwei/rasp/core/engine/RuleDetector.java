package com.zhuwei.rasp.core.engine;

import com.zhuwei.rasp.core.context.RequestContext;
import com.zhuwei.rasp.core.engine.Rule.Condition;
import com.zhuwei.rasp.core.policy.ConfigManager;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Evaluates the policy's declarative rules. Generic: contains no attack-specific knowledge. */
public final class RuleDetector implements Detector {

    @Override
    public String name() {
        return "rule";
    }

    @Override
    public boolean supports(CheckType type) {
        return true;
    }

    @Override
    public CheckResult check(CheckType type, Map<String, Object> params, RequestContext ctx) {
        CheckResult best = null;
        for (Rule r : ConfigManager.current().rulesFor(type)) {
            String[] matched = new String[1];
            if (matches(r, params, ctx, matched)) {
                best = CheckResult.max(best, new CheckResult(r.action, "rule:" + r.id, r.reason, r.confidence, matched[0]));
            }
        }
        return best == null ? CheckResult.PASS : best;
    }

    static boolean matches(Rule r, Map<String, Object> params, RequestContext ctx, String[] matched) {
        for (Condition c : r.conditions) {
            if (!eval(c, params, ctx, matched)) {
                return false;
            }
        }
        return true;
    }

    private static boolean eval(Condition c, Map<String, Object> params, RequestContext ctx, String[] matched) {
        Object raw = field(c.field, params, ctx);
        if (c.op == Rule.Op.EXISTS) {
            return raw != null && !raw.toString().isEmpty();
        }
        if (raw == null) {
            return c.op == Rule.Op.NE || c.op == Rule.Op.NOT_CONTAINS || c.op == Rule.Op.NOT_IN;
        }
        if (raw instanceof Collection) {
            for (Object o : (Collection<?>) raw) {
                if (evalOne(c, String.valueOf(o), ctx, matched)) {
                    return true;
                }
            }
            return false;
        }
        return evalOne(c, raw.toString(), ctx, matched);
    }

    private static boolean evalOne(Condition c, String s, RequestContext ctx, String[] matched) {
        String v = c.ignoreCase ? s.toLowerCase(Locale.ROOT) : s;
        switch (c.op) {
            case EQ: return v.equals(c.value);
            case NE: return !v.equals(c.value);
            case CONTAINS: return c.value != null && v.contains(c.value);
            case NOT_CONTAINS: return c.value == null || !v.contains(c.value);
            case PREFIX: return c.value != null && v.startsWith(c.value);
            case SUFFIX: return c.value != null && v.endsWith(c.value);
            case REGEX: return c.pattern != null && c.pattern.matcher(s).find();
            case IN: return c.values.contains(v);
            case NOT_IN: return !c.values.contains(v);
            case CONTAINS_USER_INPUT: return containsUserInput(s, c.minLen, ctx, matched);
            default: return false;
        }
    }

    private static boolean containsUserInput(String s, int minLen, RequestContext ctx, String[] matched) {
        if (ctx == null) {
            return false;
        }
        List<String> inputs = ctx.userInputs();
        for (String in : inputs) {
            if (in.length() >= minLen && s.contains(in)) {
                matched[0] = in;
                return true;
            }
        }
        return false;
    }

    private static Object field(String name, Map<String, Object> params, RequestContext ctx) {
        switch (name) {
            case "$in_request": return ctx == null ? "false" : "true";
            case "$url": return ctx == null ? null : ctx.url();
            case "$method": return ctx == null ? null : ctx.method();
            default: return params.get(name);
        }
    }
}
