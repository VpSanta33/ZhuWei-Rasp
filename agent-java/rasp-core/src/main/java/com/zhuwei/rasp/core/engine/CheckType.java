package com.zhuwei.rasp.core.engine;

/** Detection categories. The {@link #code} is what appears in policies, rules and alarms. */
public enum CheckType {
    SQL("sql"),
    COMMAND("command"),
    FILE_READ("readFile"),
    FILE_WRITE("writeFile"),
    SSRF("ssrf"),
    DESERIALIZATION("deserialization"),
    JNDI("jndi");

    public final String code;

    CheckType(String code) {
        this.code = code;
    }

    public static CheckType of(String code) {
        for (CheckType t : values()) {
            if (t.code.equalsIgnoreCase(code)) {
                return t;
            }
        }
        return null;
    }
}
