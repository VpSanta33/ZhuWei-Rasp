package com.zhuwei.rasp.core.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Minimal asynchronous logger. Deliberately independent of log4j/logback to avoid
 * version conflicts and recursive hooks. Writes to {@code <home>/logs/rasp.log}, rotated by size.
 */
public final class RaspLog {

    public enum Level { DEBUG, INFO, WARN, ERROR }

    private static final BlockingQueue<String> QUEUE = new ArrayBlockingQueue<>(4096);
    private static volatile Level level = Level.INFO;
    private static volatile File file;
    private static volatile long maxBytes = 50L * 1024 * 1024;
    private static volatile Thread writer;
    private static volatile boolean running;

    private RaspLog() { }

    public static synchronized void init(File logDir, String lvl, long maxSizeMb) {
        if (lvl != null) {
            try { level = Level.valueOf(lvl.trim().toUpperCase()); } catch (IllegalArgumentException ignore) { }
        }
        maxBytes = Math.max(1, maxSizeMb) * 1024 * 1024;
        if (!logDir.isDirectory() && !logDir.mkdirs()) {
            System.err.println("[ZhuWei-RASP] cannot create log dir " + logDir + ", logging to stderr");
            return;
        }
        file = new File(logDir, "rasp.log");
        if (writer == null) {
            running = true;
            writer = new Thread(RaspLog::loop, "zhuwei-rasp-log");
            writer.setDaemon(true);
            writer.start();
        }
    }

    public static synchronized void shutdown() {
        running = false;
        if (writer != null) {
            writer.interrupt();
            writer = null;
        }
    }

    public static boolean isDebug() { return level == Level.DEBUG; }

    public static void debug(String msg) { log(Level.DEBUG, msg, null); }

    public static void info(String msg) { log(Level.INFO, msg, null); }

    public static void warn(String msg) { log(Level.WARN, msg, null); }

    public static void warn(String msg, Throwable t) { log(Level.WARN, msg, t); }

    public static void error(String msg, Throwable t) { log(Level.ERROR, msg, t); }

    private static void log(Level l, String msg, Throwable t) {
        if (l.ordinal() < level.ordinal()) {
            return;
        }
        StringBuilder sb = new StringBuilder(128);
        sb.append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()))
          .append(' ').append(l).append(" [").append(Thread.currentThread().getName()).append("] ")
          .append(msg);
        if (t != null) {
            sb.append(" : ").append(t);
            StackTraceElement[] st = t.getStackTrace();
            for (int i = 0; i < Math.min(st.length, 15); i++) {
                sb.append("\n    at ").append(st[i]);
            }
        }
        sb.append('\n');
        if (file == null) {
            System.err.print("[ZhuWei-RASP] " + sb);
            return;
        }
        QUEUE.offer(sb.toString()); // drop when full, never block business threads
    }

    private static void loop() {
        Guard.markAgentThread();
        OutputStream out = null;
        long size = 0;
        while (running) {
            try {
                String line = QUEUE.poll(1, TimeUnit.SECONDS);
                if (line == null) {
                    if (out != null) { out.flush(); }
                    continue;
                }
                if (out == null) {
                    out = new FileOutputStream(file, true);
                    size = file.length();
                }
                byte[] b = line.getBytes(StandardCharsets.UTF_8);
                out.write(b);
                size += b.length;
                if (size > maxBytes) {
                    out.close();
                    out = null;
                    File old = new File(file.getPath() + ".1");
                    if (old.exists()) { old.delete(); }
                    file.renameTo(old);
                }
            } catch (InterruptedException ie) {
                break;
            } catch (Throwable t) {
                out = null;
            }
        }
        try { if (out != null) { out.close(); } } catch (Throwable ignore) { }
    }
}
