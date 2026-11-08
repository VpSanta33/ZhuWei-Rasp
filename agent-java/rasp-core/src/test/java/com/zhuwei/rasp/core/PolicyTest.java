package com.zhuwei.rasp.core;

import com.zhuwei.rasp.core.engine.Action;
import com.zhuwei.rasp.core.engine.CheckType;
import com.zhuwei.rasp.core.engine.Rule;
import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.util.Json;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyTest {

    private static RuntimeConfig cfg(String json) {
        return new RuntimeConfig(Json.parseObject(json));
    }

    @Test
    void monitorModeDowngradesBlock() {
        RuntimeConfig c = cfg("{\"mode\":\"monitor\"}");
        assertEquals(Action.LOG, c.effective(CheckType.SQL, Action.BLOCK));
        assertEquals(Action.BLOCK, cfg("{\"mode\":\"block\"}").effective(CheckType.SQL, Action.BLOCK));
    }

    @Test
    void perTypeCapAndSwitches() {
        RuntimeConfig c = cfg("{\"mode\":\"block\",\"checks\":{\"sql\":{\"action\":\"log\"},\"ssrf\":{\"enabled\":false}}}");
        assertEquals(Action.LOG, c.effective(CheckType.SQL, Action.BLOCK));
        assertEquals(Action.PASS, c.effective(CheckType.SSRF, Action.BLOCK));
        assertEquals(Action.BLOCK, c.effective(CheckType.COMMAND, Action.BLOCK));
    }

    @Test
    void killSwitchAndOffDisableEverything() {
        assertFalse(cfg("{\"mode\":\"block\",\"kill_switch\":true}").enabled(CheckType.SQL));
        assertFalse(cfg("{\"mode\":\"off\"}").enabled(CheckType.SQL));
    }

    @Test
    void whitelist() {
        RuntimeConfig c = cfg("{\"whitelist\":[{\"url\":\"/api/export\",\"match\":\"prefix\",\"types\":[\"sql\"]},"
                + "{\"url\":\"^/health$\",\"match\":\"regex\"}]}");
        assertTrue(c.whitelisted("/api/export/csv", CheckType.SQL));
        assertFalse(c.whitelisted("/api/export/csv", CheckType.COMMAND));
        assertTrue(c.whitelisted("/health", CheckType.COMMAND));
        assertFalse(c.whitelisted("/healthz", CheckType.COMMAND));
    }

    @Test
    void invalidRulesAreSkipped() {
        RuntimeConfig c = cfg("{\"rules\":[{\"id\":\"bad\",\"type\":\"nope\",\"conditions\":[]},"
                + "{\"id\":\"ok\",\"type\":\"readFile\",\"conditions\":[{\"field\":\"path\",\"op\":\"suffix\",\"value\":\".txt\"}]}]}");
        assertEquals(1, c.ruleCount());
        Rule r = c.rulesFor(CheckType.FILE_READ).get(0);
        assertEquals("ok", r.id);
        assertEquals(Action.LOG, r.action);
    }
}
