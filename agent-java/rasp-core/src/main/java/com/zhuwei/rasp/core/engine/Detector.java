package com.zhuwei.rasp.core.engine;

import com.zhuwei.rasp.core.context.RequestContext;

import java.util.Map;

/**
 * Extension point for detection algorithms.
 *
 * <p>The MVP ships only {@link RuleDetector}, a generic condition engine driven by policy rules.
 * Type-specific algorithms (designed by the security research team, see docs chapter 5) are added by
 * implementing this interface and registering it in {@link DetectEngine}.</p>
 *
 * <p>Implementations must be thread-safe, fast (budget: well under 1ms) and must never throw.</p>
 */
public interface Detector {

    String name();

    boolean supports(CheckType type);

    /**
     * @param params values extracted by the hook (see HookRegistry)
     * @param ctx    current HTTP request, or null outside a request (scheduled jobs, MQ consumers ...)
     */
    CheckResult check(CheckType type, Map<String, Object> params, RequestContext ctx);
}
