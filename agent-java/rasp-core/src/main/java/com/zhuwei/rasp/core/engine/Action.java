package com.zhuwei.rasp.core.engine;

/** Ordered by severity, so the highest ordinal wins when merging results. */
public enum Action {
    PASS, LOG, BLOCK;

    public static Action of(String s, Action def) {
        if (s == null) {
            return def;
        }
        switch (s.trim().toLowerCase()) {
            case "pass":
            case "ignore":
                return PASS;
            case "log":
                return LOG;
            case "block":
                return BLOCK;
            default:
                return def;
        }
    }

    public String code() {
        return name().toLowerCase();
    }
}
