package com.zhuwei.rasp.core.policy;

import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.RaspLog;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Holds the current {@link RuntimeConfig}. Load order at startup:
 * cached server config ({@code cache/config.json}) &gt; {@code conf/policy.json} &gt; built-in defaults.
 *
 * <p>Server configs (and the cache, which stores the signed envelope as received) go through
 * {@link PolicyVerifier}: signature, app binding ({@code app_key}) and rollback protection
 * ({@code issued_at} must not go backwards). {@code conf/policy.json} is trusted like
 * {@code conf/rasp.properties}, i.e. by file permissions.</p>
 */
public final class ConfigManager {

    private static volatile RuntimeConfig current = RuntimeConfig.defaults();
    private static volatile File cacheFile;
    private static volatile PolicyVerifier verifier = PolicyVerifier.none();
    private static volatile String appKey = "";
    private static long issuedAt;
    private static final AtomicLong rejected = new AtomicLong();
    private static volatile String lastRejectReason = "";
    private static boolean warnedUnverified;

    private ConfigManager() { }

    public static RuntimeConfig current() {
        return current;
    }

    /** Number of server configs refused since start (reported in heartbeat metrics). */
    public static long rejectedCount() {
        return rejected.get();
    }

    public static String lastRejectReason() {
        return lastRejectReason;
    }

    public static void init(File home) {
        init(home, PolicyVerifier.none(), "");
    }

    public static synchronized void init(File home, PolicyVerifier v, String key) {
        verifier = v;
        appKey = key == null ? "" : key;
        issuedAt = 0;
        current = RuntimeConfig.defaults();
        File cacheDir = new File(home, "cache");
        cacheDir.mkdirs();
        cacheFile = new File(cacheDir, "config.json");
        if (cacheFile.isFile()) {
            try {
                String s = new String(Files.readAllBytes(cacheFile.toPath()), StandardCharsets.UTF_8);
                apply(Json.parseObject(s), false);
                RaspLog.info("loaded cached server config version=" + current.version
                        + " mode=" + current.mode + " rules=" + current.ruleCount());
                return;
            } catch (Exception e) {
                RaspLog.warn("ignoring cached config " + cacheFile + ": " + e.getMessage());
            }
        }
        File local = new File(home, "conf/policy.json");
        if (local.isFile()) {
            try {
                String s = new String(Files.readAllBytes(local.toPath()), StandardCharsets.UTF_8);
                current = new RuntimeConfig(Json.parseObject(s));
                RaspLog.info("loaded config from " + local + " version=" + current.version
                        + " mode=" + current.mode + " rules=" + current.ruleCount());
                return;
            } catch (Exception e) {
                RaspLog.warn("cannot load config " + local + ": " + e.getMessage());
            }
        }
        RaspLog.info("using built-in default config (monitor mode, no rules)");
    }

    /**
     * Applies a config received from the server ({@code data} of GET /agent/v1/config) and caches the
     * envelope for the next start.
     *
     * @return false when the config was rejected (the current config stays in force)
     */
    public static synchronized boolean update(Map<String, Object> data) {
        try {
            apply(data, true);
        } catch (PolicyVerifier.Rejected e) {
            rejected.incrementAndGet();
            lastRejectReason = e.getMessage();
            RaspLog.warn("REJECTED server config: " + e.getMessage() + "; keeping version=" + current.version);
            return false;
        }
        RaspLog.info("config updated version=" + current.version + " mode=" + current.mode
                + " kill_switch=" + current.killSwitch + " rules=" + current.ruleCount()
                + (data.get("payload") instanceof String && verifier.hasKey() ? " (signature ok)" : ""));
        if (cacheFile != null) {
            try {
                File tmp = new File(cacheFile.getPath() + ".tmp");
                Files.write(tmp.toPath(), Json.stringify(data).getBytes(StandardCharsets.UTF_8));
                Files.move(tmp.toPath(), cacheFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception e) {
                RaspLog.warn("cannot cache config: " + e.getMessage());
            }
        }
        return true;
    }

    private static void apply(Map<String, Object> data, boolean fromServer) throws PolicyVerifier.Rejected {
        Map<String, Object> p = verifier.open(data);
        String boundKey = Json.str(p, "app_key", "");
        if (!boundKey.isEmpty() && !appKey.isEmpty() && !boundKey.equals(appKey)) {
            throw new PolicyVerifier.Rejected("config is for another app (app_key " + boundKey + ")");
        }
        long ts = Json.num(p, "issued_at", 0);
        if (ts < issuedAt) {
            throw new PolicyVerifier.Rejected("config issued_at " + ts + " is older than the current one ("
                    + issuedAt + "), possible replay");
        }
        if (fromServer && !verifier.hasKey() && !warnedUnverified) {
            warnedUnverified = true;
            RaspLog.warn("policy.public_key is not set: server configs are applied WITHOUT signature verification");
        }
        current = new RuntimeConfig(p);
        issuedAt = ts;
    }
}
