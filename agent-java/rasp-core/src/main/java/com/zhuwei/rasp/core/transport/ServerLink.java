package com.zhuwei.rasp.core.transport;

import com.zhuwei.rasp.core.breaker.Breaker;
import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.RaspLog;

import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Register + heartbeat + config pull (docs chapter 7.3). Runs entirely on a daemon thread;
 * a missing or broken server never affects the application.
 */
public final class ServerLink {

    public static final String AGENT_VERSION = "0.1.0";

    private final AgentClient client;
    private final Reporter reporter;
    private final String appName;
    private final String env;
    private final boolean attach;
    private final String agentId = UUID.randomUUID().toString();
    private volatile boolean running;
    private volatile int heartbeatSec = 30;
    private Thread thread;

    public ServerLink(AgentClient client, Reporter reporter, String appName, String env, boolean attach) {
        this.client = client;
        this.reporter = reporter;
        this.appName = appName;
        this.env = env;
        this.attach = attach;
    }

    private volatile boolean registered;
    private volatile Runnable onRegistered;

    /** Callback run on the heartbeat thread after each successful (re-)registration. */
    public void setOnRegistered(Runnable r) {
        this.onRegistered = r;
    }

    /**
     * POSTs a JSON body when connected.
     * @return null when not registered yet, otherwise whether the server accepted it
     */
    public Boolean postIfRegistered(String path, String json) {
        if (!registered) {
            return null;
        }
        try {
            AgentClient.Response r = client.post(path, json);
            if (!r.ok()) {
                RaspLog.warn("POST " + path + " rejected: HTTP " + r.status + " " + r.body);
            }
            return r.ok();
        } catch (Exception e) {
            RaspLog.warn("POST " + path + " failed: " + e);
            return false;
        }
    }

    public synchronized void start() {
        running = true;
        thread = new Thread(this::loop, "zhuwei-rasp-heartbeat");
        thread.setDaemon(true);
        thread.start();
    }

    public synchronized void stop() {
        running = false;
        if (thread != null) {
            thread.interrupt();
        }
    }

    private void loop() {
        Guard.markAgentThread();
        registered = false;
        long retry = 5_000;
        while (running) {
            try {
                if (!registered) {
                    if (register()) {
                        reporter.connect(client, agentId);
                        pullConfig();
                        registered = true;
                        retry = 5_000;
                        Runnable cb = onRegistered;
                        if (cb != null) {
                            cb.run();
                        }
                    }
                } else if (!heartbeat()) {
                    registered = false;
                }
            } catch (Exception e) {
                RaspLog.warn("server communication failed: " + e);
            }
            try {
                Thread.sleep(registered ? heartbeatSec * 1000L : retry);
            } catch (InterruptedException e) {
                return;
            }
            if (!registered) {
                retry = Math.min(retry * 2, 300_000);
            }
        }
    }

    private boolean register() throws Exception {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("agent_id", agentId);
        b.put("language", "java");
        b.put("agent_version", AGENT_VERSION);
        b.put("app_name", appName);
        b.put("env", env);
        b.put("hostname", hostname());
        b.put("ips", ips());
        b.put("pid", ProcessHandle.current().pid());
        b.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version") + " " + System.getProperty("os.arch"));
        Map<String, Object> rt = new LinkedHashMap<>();
        rt.put("name", System.getProperty("java.vm.vendor"));
        rt.put("version", System.getProperty("java.version"));
        rt.put("vm", System.getProperty("java.vm.name"));
        b.put("runtime", rt);
        Map<String, Object> srv = new LinkedHashMap<>();
        srv.put("type", detectServer());
        b.put("server", srv);
        b.put("start_mode", attach ? "attach" : "premain");
        b.put("started_at", ManagementFactory.getRuntimeMXBean().getStartTime());

        client.setAgentId(agentId);
        AgentClient.Response r = client.post("/agent/v1/register", Json.stringify(b));
        if (!r.ok()) {
            RaspLog.warn("register failed: HTTP " + r.status + " " + r.body);
            return false;
        }
        Map<String, Object> data = Json.obj(Json.parseObject(r.body), "data");
        heartbeatSec = (int) Math.max(5, Json.num(data, "heartbeat_interval", 30));
        RaspLog.info("registered to server, agent_id=" + agentId + " app=" + appName);
        return true;
    }

    private boolean heartbeat() throws Exception {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("agent_id", agentId);
        b.put("config_version", ConfigManager.current().version);
        b.put("status", "running");
        Map<String, Object> m = new LinkedHashMap<>();
        Runtime rt = Runtime.getRuntime();
        m.put("heap_used_mb", (rt.totalMemory() - rt.freeMemory()) / 1024 / 1024);
        m.put("hook_count_window", Breaker.lastHooksPerWindow());
        m.put("check_avg_us", Breaker.lastAvgMicros());
        m.put("alarm_dropped", reporter.dropped());
        m.put("alarm_sent", reporter.sent());
        m.put("breaker_state", Breaker.state().name().toLowerCase());
        m.put("config_rejected", ConfigManager.rejectedCount());
        if (ConfigManager.rejectedCount() > 0) {
            m.put("config_reject_reason", ConfigManager.lastRejectReason());
        }
        b.put("metrics", m);
        AgentClient.Response r = client.post("/agent/v1/heartbeat", Json.stringify(b));
        if (r.status == 404) {
            RaspLog.warn("server does not know this agent, re-registering");
            return false;
        }
        if (!r.ok()) {
            RaspLog.warn("heartbeat failed: HTTP " + r.status);
            return true;
        }
        Map<String, Object> data = Json.obj(Json.parseObject(r.body), "data");
        if (Json.bool(data, "config_changed", false)) {
            pullConfig();
        }
        return true;
    }

    private void pullConfig() throws Exception {
        AgentClient.Response r = client.get("/agent/v1/config");
        if (!r.ok()) {
            RaspLog.warn("config pull failed: HTTP " + r.status);
            return;
        }
        Map<String, Object> data = Json.obj(Json.parseObject(r.body), "data");
        if (!data.isEmpty()) {
            ConfigManager.update(data);
        }
    }

    private static String hostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            String h = System.getenv("HOSTNAME");
            return h == null ? "unknown" : h;
        }
    }

    private static List<String> ips() {
        List<String> out = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) {
                    continue;
                }
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a.getAddress().length == 4) {
                        out.add(a.getHostAddress());
                    }
                }
            }
        } catch (Exception ignore) {
            // best effort
        }
        return out;
    }

    private static String detectServer() {
        if (System.getProperty("catalina.home") != null) {
            return "tomcat";
        }
        if (System.getProperty("jetty.home") != null) {
            return "jetty";
        }
        if (System.getProperty("jboss.home.dir") != null) {
            return "jboss";
        }
        if (System.getProperty("weblogic.Name") != null) {
            return "weblogic";
        }
        return "unknown";
    }
}
