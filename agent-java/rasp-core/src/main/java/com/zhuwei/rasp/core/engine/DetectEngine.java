package com.zhuwei.rasp.core.engine;

import com.zhuwei.rasp.core.context.RequestContext;
import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.util.RaspLog;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** Runs all detectors for a check type and applies policy (whitelist, per-type cap, mode). */
public final class DetectEngine {

    private static final List<Detector> DETECTORS = new CopyOnWriteArrayList<>();

    static {
        DETECTORS.add(new RuleDetector());
    }

    private DetectEngine() { }

    /** Registers an additional (type-specific) detector. */
    public static void register(Detector d) {
        DETECTORS.add(d);
        RaspLog.info("detector registered: " + d.name());
    }

    /** @return the final result after policy, or {@link CheckResult#PASS}. */
    public static CheckResult check(CheckType type, Map<String, Object> params, RequestContext ctx) {
        RuntimeConfig cfg = ConfigManager.current();
        if (!cfg.enabled(type)) {
            return CheckResult.PASS;
        }
        if (ctx != null && cfg.whitelisted(ctx.uri(), type)) {
            return CheckResult.PASS;
        }
        CheckResult best = null;
        for (Detector d : DETECTORS) {
            if (!d.supports(type)) {
                continue;
            }
            CheckResult r;
            try {
                r = d.check(type, params, ctx);
            } catch (Throwable t) {
                RaspLog.warn("detector " + d.name() + " failed", t);
                continue;
            }
            best = CheckResult.max(best, r);
        }
        if (best == null || best.action == Action.PASS) {
            return CheckResult.PASS;
        }
        Action eff = cfg.effective(type, best.action);
        return eff == best.action ? best : best.withAction(eff);
    }
}
