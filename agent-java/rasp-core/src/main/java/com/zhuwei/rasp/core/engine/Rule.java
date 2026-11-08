package com.zhuwei.rasp.core.engine;

import com.zhuwei.rasp.core.util.Json;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * A declarative rule: all conditions must hold (AND). Rules are part of the policy pushed by the server.
 *
 * <pre>
 * {
 *   "id": "file-read-user-input", "type": "readFile", "action": "log", "confidence": 60,
 *   "reason": "file path contains user input",
 *   "conditions": [ { "field": "path", "op": "contains_user_input", "min_len": 4 } ]
 * }
 * </pre>
 *
 * Fields: any hook parameter (see HookRegistry), plus {@code $in_request}, {@code $url}, {@code $method}.
 */
public final class Rule {

    public final String id;
    public final CheckType type;
    public final Action action;
    public final String reason;
    public final int confidence;
    public final List<Condition> conditions;

    private Rule(String id, CheckType type, Action action, String reason, int confidence, List<Condition> conditions) {
        this.id = id;
        this.type = type;
        this.action = action;
        this.reason = reason;
        this.confidence = confidence;
        this.conditions = conditions;
    }

    @SuppressWarnings("unchecked")
    public static Rule parse(Map<String, Object> m) {
        CheckType type = CheckType.of(Json.str(m, "type", ""));
        if (type == null) {
            throw new IllegalArgumentException("unknown rule type: " + m.get("type"));
        }
        List<Condition> cs = new ArrayList<>();
        for (Object o : Json.list(m, "conditions")) {
            if (o instanceof Map) {
                cs.add(Condition.parse((Map<String, Object>) o));
            }
        }
        if (cs.isEmpty()) {
            throw new IllegalArgumentException("rule " + m.get("id") + " has no conditions");
        }
        return new Rule(Json.str(m, "id", "rule"), type, Action.of(Json.str(m, "action", "log"), Action.LOG),
                Json.str(m, "reason", ""), (int) Json.num(m, "confidence", 50), Collections.unmodifiableList(cs));
    }

    public enum Op {
        EQ, NE, CONTAINS, NOT_CONTAINS, PREFIX, SUFFIX, REGEX, IN, NOT_IN, EXISTS, CONTAINS_USER_INPUT;

        static Op of(String s) {
            return Op.valueOf(s.trim().toUpperCase(Locale.ROOT));
        }
    }

    public static final class Condition {
        public final String field;
        public final Op op;
        public final String value;
        public final List<String> values;
        public final boolean ignoreCase;
        public final int minLen;
        public final Pattern pattern;

        private Condition(String field, Op op, String value, List<String> values, boolean ignoreCase, int minLen) {
            this.field = field;
            this.op = op;
            this.ignoreCase = ignoreCase;
            this.minLen = minLen;
            this.value = value == null ? null : (ignoreCase ? value.toLowerCase(Locale.ROOT) : value);
            List<String> vs = new ArrayList<>();
            for (String v : values) {
                vs.add(ignoreCase ? v.toLowerCase(Locale.ROOT) : v);
            }
            this.values = Collections.unmodifiableList(vs);
            this.pattern = op == Op.REGEX && value != null
                    ? Pattern.compile(value, ignoreCase ? Pattern.CASE_INSENSITIVE : 0) : null;
        }

        static Condition parse(Map<String, Object> m) {
            Object raw = m.get("value");
            List<String> values = new ArrayList<>();
            String single = null;
            if (raw instanceof Collection) {
                for (Object o : (Collection<?>) raw) {
                    values.add(String.valueOf(o));
                }
            } else if (raw != null) {
                single = String.valueOf(raw);
            }
            return new Condition(Json.str(m, "field", ""), Op.of(Json.str(m, "op", "eq")), single, values,
                    Json.bool(m, "ignore_case", false), (int) Json.num(m, "min_len", 4));
        }
    }
}
