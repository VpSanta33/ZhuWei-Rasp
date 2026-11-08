package com.zhuwei.rasp.core.policy;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

/**
 * Local, static agent settings from {@code conf/rasp.properties}.
 * Precedence: JVM {@code -Drasp.x.y} &gt; env {@code RASP_X_Y} &gt; agent args {@code x.y=v;...} &gt; file &gt; default.
 */
public final class AgentSettings {

    private final Properties file = new Properties();
    private final Properties args = new Properties();
    public final File home;

    public AgentSettings(File home, String agentArgs) {
        this.home = home;
        File f = new File(home, "conf/rasp.properties");
        if (f.isFile()) {
            try (InputStream in = new FileInputStream(f)) {
                file.load(new InputStreamReader(in, StandardCharsets.UTF_8));
            } catch (Exception e) {
                System.err.println("[ZhuWei-RASP] cannot read " + f + ": " + e);
            }
        }
        if (agentArgs != null) {
            for (String kv : agentArgs.split(";")) {
                int i = kv.indexOf('=');
                if (i > 0) {
                    args.setProperty(kv.substring(0, i).trim(), kv.substring(i + 1).trim());
                }
            }
        }
    }

    public String get(String key, String def) {
        String v = System.getProperty("rasp." + key);
        if (v == null) {
            v = System.getenv("RASP_" + key.toUpperCase().replace('.', '_'));
        }
        if (v == null) {
            v = args.getProperty(key);
        }
        if (v == null) {
            v = file.getProperty(key);
        }
        return v == null || v.trim().isEmpty() ? def : v.trim();
    }

    public long getLong(String key, long def) {
        try {
            return Long.parseLong(get(key, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    public boolean getBool(String key, boolean def) {
        return Boolean.parseBoolean(get(key, String.valueOf(def)));
    }
}
