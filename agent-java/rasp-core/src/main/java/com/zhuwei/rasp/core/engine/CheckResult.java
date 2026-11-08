package com.zhuwei.rasp.core.engine;

/** Outcome of one detector. */
public final class CheckResult {

    public static final CheckResult PASS = new CheckResult(Action.PASS, null, null, 0, null);

    public final Action action;
    public final String algorithm;
    public final String reason;
    public final int confidence;
    /** The user input that triggered the result, if any. */
    public final String matchedInput;

    public CheckResult(Action action, String algorithm, String reason, int confidence, String matchedInput) {
        this.action = action;
        this.algorithm = algorithm;
        this.reason = reason;
        this.confidence = confidence;
        this.matchedInput = matchedInput;
    }

    public CheckResult withAction(Action a) {
        return new CheckResult(a, algorithm, reason, confidence, matchedInput);
    }

    public static CheckResult max(CheckResult a, CheckResult b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        if (b.action.ordinal() != a.action.ordinal()) {
            return b.action.ordinal() > a.action.ordinal() ? b : a;
        }
        return b.confidence > a.confidence ? b : a;
    }
}
