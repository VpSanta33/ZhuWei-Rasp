package com.zhuwei.rasp.core.transport;

import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.RaspLog;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Asynchronous alarm reporter. Business threads only do a non-blocking {@code offer}.
 * Every alarm is also appended to {@code logs/alarm.log} (JSON lines), so nothing is lost when the
 * server is unreachable or when the agent runs without a server.
 */
public final class Reporter {

    private static final int BATCH = 100;
    private static final long MAX_ALARM_LOG = 100L * 1024 * 1024;

    private final BlockingQueue<Map<String, Object>> queue;
    private final File alarmLog;
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private volatile AgentClient client;
    private volatile String agentId;
    private volatile boolean running;
    private Thread thread;

    public Reporter(File logDir, int capacity) {
        this.queue = new ArrayBlockingQueue<>(Math.max(100, capacity));
        this.alarmLog = new File(logDir, "alarm.log");
    }

    public void connect(AgentClient c, String id) {
        this.client = c;
        this.agentId = id;
    }

    public void offer(Map<String, Object> alarm) {
        if (!queue.offer(alarm)) {
            dropped.incrementAndGet();
        }
    }

    public long dropped() {
        return dropped.get();
    }

    public long sent() {
        return sent.get();
    }

    public synchronized void start() {
        running = true;
        thread = new Thread(this::loop, "zhuwei-rasp-reporter");
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
        List<Map<String, Object>> batch = new ArrayList<>(BATCH);
        long backoffUntil = 0;
        while (running) {
            try {
                Map<String, Object> first = queue.poll(2, TimeUnit.SECONDS);
                if (first == null) {
                    continue;
                }
                batch.add(first);
                queue.drainTo(batch, BATCH - 1);
                writeLocal(batch);
                AgentClient c = client;
                if (c != null && System.currentTimeMillis() >= backoffUntil) {
                    if (send(c, batch)) {
                        sent.addAndGet(batch.size());
                    } else {
                        backoffUntil = System.currentTimeMillis() + 30_000;
                    }
                }
            } catch (InterruptedException e) {
                return;
            } catch (Throwable t) {
                RaspLog.warn("reporter loop error", t);
            } finally {
                batch.clear();
            }
        }
    }

    private boolean send(AgentClient c, List<Map<String, Object>> batch) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_id", agentId);
        body.put("events", batch);
        try {
            AgentClient.Response r = c.post("/agent/v1/alarms", Json.stringify(body));
            if (!r.ok()) {
                RaspLog.warn("alarm upload rejected: HTTP " + r.status + " " + r.body);
            }
            return r.ok();
        } catch (Exception e) {
            RaspLog.warn("alarm upload failed: " + e);
            return false;
        }
    }

    private void writeLocal(List<Map<String, Object>> batch) {
        try {
            if (alarmLog.length() > MAX_ALARM_LOG) {
                File old = new File(alarmLog.getPath() + ".1");
                old.delete();
                alarmLog.renameTo(old);
            }
            try (OutputStream os = new FileOutputStream(alarmLog, true)) {
                for (Map<String, Object> a : batch) {
                    os.write((Json.stringify(a) + "\n").getBytes(StandardCharsets.UTF_8));
                }
            }
        } catch (Exception e) {
            RaspLog.warn("cannot write alarm.log: " + e);
        }
    }
}
