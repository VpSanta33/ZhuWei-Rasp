package com.zhuwei.rasp.core;

import com.zhuwei.rasp.bootstrap.Spy;
import com.zhuwei.rasp.core.breaker.Breaker;
import com.zhuwei.rasp.core.hook.RaspSpyHandler;
import com.zhuwei.rasp.core.policy.AgentSettings;
import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.policy.PolicyVerifier;
import com.zhuwei.rasp.core.sca.DependencyScanner;
import com.zhuwei.rasp.core.transform.RaspTransformer;
import com.zhuwei.rasp.core.transport.AgentClient;
import com.zhuwei.rasp.core.transport.Reporter;
import com.zhuwei.rasp.core.transport.ServerLink;
import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.Jdk;
import com.zhuwei.rasp.core.util.RaspLog;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Entry point of rasp-core, invoked reflectively by the launcher inside RaspClassLoader. */
public final class CoreEngine {

    private static Instrumentation inst;
    private static RaspTransformer transformer;
    private static Reporter reporter;
    private static ServerLink link;
    private static DependencyScanner scanner;

    private CoreEngine() { }

    public static synchronized void start(Instrumentation instrumentation, String args, String homePath, boolean attach) {
        boolean acquired = Guard.enter();
        try {
            long t0 = System.currentTimeMillis();
            inst = instrumentation;
            File home = new File(homePath);
            AgentSettings s = new AgentSettings(home, args);
            RaspLog.init(new File(home, "logs"), s.get("log.level", "INFO"), s.getLong("log.max_size_mb", 50));
            RaspLog.info("ZhuWei-RASP " + ServerLink.AGENT_VERSION + " starting, home=" + home
                    + " java=" + System.getProperty("java.version") + " mode=" + (attach ? "attach" : "premain"));

            PolicyVerifier verifier;
            try {
                verifier = PolicyVerifier.fromSettings(s.get("policy.public_key", ""), s.get("policy.require_signature", ""));
            } catch (Exception e) {
                RaspLog.error("invalid policy.public_key, all server configs will be rejected", e);
                verifier = new PolicyVerifier(null, true);
            }
            ConfigManager.init(home, verifier, s.get("app.key", ""));
            reporter = new Reporter(new File(home, "logs"), (int) s.getLong("report.queue_size", 2000));
            reporter.start();
            Breaker.start(home);

            String server = s.get("server.url", "");
            if (!server.isEmpty()) {
                AgentClient client = new AgentClient(server, s.get("app.key", ""), s.get("app.secret", ""));
                link = new ServerLink(client, reporter, s.get("app.name", "unknown-app"), s.get("app.env", "prod"), attach);
            } else {
                RaspLog.info("server.url not set: standalone mode, alarms go to logs/alarm.log only");
            }
            if (s.getBool("sca.enabled", true)) {
                ServerLink l = link;
                scanner = new DependencyScanner(inst, home,
                        json -> l == null ? null : l.postIfRegistered("/agent/v1/dependencies", json),
                        s.getLong("sca.initial_delay_sec", 30) * 1000L,
                        Math.max(1, s.getLong("sca.interval_min", 10)) * 60_000L);
                if (link != null) {
                    link.setOnRegistered(scanner::requestReport);
                }
                scanner.start();
            }
            if (link != null) {
                link.start();
            }

            Object spyModule = Jdk.moduleOf(Spy.class); // null on JDK 8
            Jdk.allowBootModulesToRead(inst, Spy.class);
            Spy.install(new RaspSpyHandler(reporter));

            File dump = s.getBool("debug.dump", false) ? new File(home, "dump") : null;
            transformer = new RaspTransformer(inst, spyModule, dump);
            inst.addTransformer(transformer, true);
            retransformLoaded();

            RaspLog.info("ZhuWei-RASP started in " + (System.currentTimeMillis() - t0) + "ms, policy mode="
                    + ConfigManager.current().mode);
            System.err.println("[ZhuWei-RASP] started, logs: " + new File(home, "logs"));
        } catch (Throwable t) {
            RaspLog.error("start failed, disabling RASP", t);
            safeStop();
        } finally {
            if (acquired) {
                Guard.exit();
            }
        }
    }

    private static void retransformLoaded() {
        List<Class<?>> targets = new ArrayList<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            try {
                if (transformer.shouldRetransform(c)) {
                    targets.add(c);
                }
            } catch (Throwable ignore) {
                // some classes cannot be inspected
            }
        }
        for (Class<?> c : targets) {
            try {
                inst.retransformClasses(c);
            } catch (Throwable t) {
                RaspLog.warn("retransform failed for " + c.getName() + ": " + t);
            }
        }
    }

    /** Called by the launcher on {@code agentmain("uninstall")}. Restores original bytecode. */
    public static synchronized void stop() {
        RaspLog.info("ZhuWei-RASP stopping");
        safeStop();
    }

    private static void safeStop() {
        try {
            Spy.uninstall();
            if (transformer != null && inst != null) {
                transformer.disable();
                inst.removeTransformer(transformer);
                List<Class<?>> restore = new ArrayList<>();
                for (Class<?> c : inst.getAllLoadedClasses()) {
                    if (transformer.transformedClasses().contains(c.getName())) {
                        restore.add(c);
                    }
                }
                for (Class<?> c : restore) {
                    try {
                        inst.retransformClasses(c);
                    } catch (Throwable ignore) {
                        // best effort
                    }
                }
            }
            if (link != null) {
                link.stop();
            }
            if (scanner != null) {
                scanner.stop();
            }
            if (reporter != null) {
                reporter.stop();
            }
            Breaker.stop();
            RaspLog.shutdown();
        } catch (Throwable ignore) {
            // nothing else we can do
        } finally {
            transformer = null;
            link = null;
            scanner = null;
            reporter = null;
        }
    }
}
