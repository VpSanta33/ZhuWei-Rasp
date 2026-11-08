package com.zhuwei.rasp.core.policy;

import com.zhuwei.rasp.core.engine.Action;
import com.zhuwei.rasp.core.engine.CheckType;
import com.zhuwei.rasp.core.engine.Rule;
import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.RaspLog;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Immutable effective configuration (policy + rules + whitelist) as delivered by the server.
 * Replaced atomically by {@link ConfigManager}; readers never see a half-updated config.
 */
public final class RuntimeConfig {

    public enum Mode { OFF, MONITOR, BLOCK }

    public static final String DEFAULT_HTML = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>403</title></head>"
            + "<body style=\"font-family:sans-serif;text-align:center;padding-top:80px\"><h2>请求已被安全策略拦截</h2>"
            + "<p>Request blocked by security policy.</p><p style=\"color:#888\">request_id: %request_id%</p></body></html>";
    public static final String DEFAULT_JSON = "{\"code\":403,\"message\":\"blocked by security policy\",\"request_id\":\"%request_id%\"}";

    public final String version;
    public final Mode mode;
    public final boolean killSwitch;
    public final boolean readFormParams;
    /** Max request body bytes copied per request (0 = body capture off). */
    public final int bodyMaxBytes;
    /** Propagate request context into ThreadPoolExecutor tasks. */
    public final boolean asyncContext;
    public final int blockStatus;
    public final String blockHtml;
    public final String blockJson;
    public final long breakerAvgCheckMicros;
    public final long breakerErrorsPerWindow;
    public final int breakerWindowSec;
    public final int breakerRecoverSec;
    public final int stackDepth;
    public final Set<String> maskHeaders;
    public final Set<String> maskParams;

    private final Map<CheckType, Boolean> enabled = new EnumMap<>(CheckType.class);
    private final Map<CheckType, Action> maxAction = new EnumMap<>(CheckType.class);
    private final Map<CheckType, List<Rule>> rules = new EnumMap<>(CheckType.class);
    private final List<WhitelistEntry> whitelist;

    @SuppressWarnings("unchecked")
    public RuntimeConfig(Map<String, Object> m) {
        version = Json.str(m, "version", "local");
        Mode md;
        try {
            md = Mode.valueOf(Json.str(m, "mode", "monitor").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            md = Mode.MONITOR;
        }
        mode = md;
        killSwitch = Json.bool(m, "kill_switch", false);
        readFormParams = Json.bool(m, "read_form_params", false);
        bodyMaxBytes = (int) Math.max(0, Math.min(1 << 20, Json.num(m, "body_max_bytes", 65536)));
        asyncContext = Json.bool(m, "async_context", true);

        Map<String, Object> checks = Json.obj(m, "checks");
        for (CheckType t : CheckType.values()) {
            Map<String, Object> c = Json.obj(checks, t.code);
            enabled.put(t, Json.bool(c, "enabled", true));
            maxAction.put(t, Action.of(Json.str(c, "action", "block"), Action.BLOCK));
            rules.put(t, new ArrayList<>());
        }
        for (Object o : Json.list(m, "rules")) {
            if (!(o instanceof Map)) {
                continue;
            }
            Map<String, Object> rm = (Map<String, Object>) o;
            if (!Json.bool(rm, "enabled", true)) {
                continue;
            }
            try {
                Rule r = Rule.parse(rm);
                rules.get(r.type).add(r);
            } catch (Exception e) {
                RaspLog.warn("skip invalid rule " + rm.get("id") + ": " + e.getMessage());
            }
        }

        List<WhitelistEntry> wl = new ArrayList<>();
        for (Object o : Json.list(m, "whitelist")) {
            if (o instanceof Map) {
                try {
                    wl.add(new WhitelistEntry((Map<String, Object>) o));
                } catch (Exception e) {
                    RaspLog.warn("skip invalid whitelist entry: " + e.getMessage());
                }
            }
        }
        whitelist = Collections.unmodifiableList(wl);

        Map<String, Object> br = Json.obj(m, "block_response");
        blockStatus = (int) Json.num(br, "status", 403);
        blockHtml = Json.str(br, "html", DEFAULT_HTML);
        blockJson = Json.str(br, "json", DEFAULT_JSON);

        Map<String, Object> bk = Json.obj(m, "breaker");
        breakerAvgCheckMicros = Json.num(bk, "avg_check_us", 2000);
        breakerErrorsPerWindow = Json.num(bk, "errors_per_window", 200);
        breakerWindowSec = (int) Math.max(1, Json.num(bk, "window_sec", 10));
        breakerRecoverSec = (int) Math.max(10, Json.num(bk, "recover_sec", 300));

        stackDepth = (int) Json.num(Json.obj(m, "report"), "stack_depth", 50);
        Map<String, Object> pv = Json.obj(m, "privacy");
        maskHeaders = lowerSet(Json.list(pv, "mask_headers"), "cookie", "authorization");
        maskParams = lowerSet(Json.list(pv, "mask_params"), "password", "passwd", "pwd", "token", "secret");
    }

    public static RuntimeConfig defaults() {
        return new RuntimeConfig(Collections.emptyMap());
    }

    public boolean enabled(CheckType t) {
        return mode != Mode.OFF && !killSwitch && enabled.get(t);
    }

    public List<Rule> rulesFor(CheckType t) {
        return rules.get(t);
    }

    public int ruleCount() {
        int n = 0;
        for (List<Rule> l : rules.values()) {
            n += l.size();
        }
        return n;
    }

    /** Applies the per-type cap and the global mode to a detector's proposed action. */
    public Action effective(CheckType t, Action proposed) {
        if (!enabled(t)) {
            return Action.PASS;
        }
        Action a = proposed.ordinal() > maxAction.get(t).ordinal() ? maxAction.get(t) : proposed;
        if (mode == Mode.MONITOR && a == Action.BLOCK) {
            a = Action.LOG;
        }
        return a;
    }

    public boolean whitelisted(String uri, CheckType t) {
        if (uri == null) {
            return false;
        }
        for (WhitelistEntry w : whitelist) {
            if (w.matches(uri, t)) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> lowerSet(List<Object> l, String... defaults) {
        Set<String> s = new HashSet<>();
        if (l.isEmpty()) {
            for (String d : defaults) {
                s.add(d);
            }
        }
        for (Object o : l) {
            s.add(String.valueOf(o).toLowerCase(Locale.ROOT));
        }
        return Collections.unmodifiableSet(s);
    }

    /** URL (+ check types) whitelist entry. match: exact | prefix | regex. */
    static final class WhitelistEntry {
        final String url;
        final String match;
        final Pattern pattern;
        final Set<CheckType> types = new HashSet<>();
        final boolean allTypes;

        WhitelistEntry(Map<String, Object> m) {
            url = Json.str(m, "url", "");
            match = Json.str(m, "match", "prefix");
            pattern = "regex".equals(match) ? Pattern.compile(url) : null;
            boolean all = false;
            for (Object o : Json.list(m, "types")) {
                String s = String.valueOf(o);
                if ("all".equals(s)) {
                    all = true;
                } else {
                    CheckType t = CheckType.of(s);
                    if (t != null) {
                        types.add(t);
                    }
                }
            }
            allTypes = all || types.isEmpty();
        }

        boolean matches(String uri, CheckType t) {
            if (!allTypes && !types.contains(t)) {
                return false;
            }
            switch (match) {
                case "exact": return uri.equals(url);
                case "regex": return pattern.matcher(uri).find();
                default: return uri.startsWith(url);
            }
        }
    }
}
