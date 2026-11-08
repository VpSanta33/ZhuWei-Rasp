package com.zhuwei.rasp.core.sca;

import com.zhuwei.rasp.core.util.Guard;
import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.RaspLog;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.function.Function;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Software composition inventory: which third-party jars (and versions) the application has actually
 * loaded classes from. Runs on its own low-priority daemon thread; never touches business threads.
 *
 * <p>Identification order: {@code META-INF/maven/**}/pom.properties (one item per pom, so shaded/uber
 * jars list their bundled libraries), then MANIFEST Implementation/Bundle headers, then the file name.</p>
 */
public final class DependencyScanner {

    private static final int MAX_ITEMS = 3000;
    private static final long MAX_NESTED_BYTES = 200L * 1024 * 1024;
    private static final Pattern FILE_VERSION = Pattern.compile("^(.+?)-(\\d[\\w.\\-+]*)\\.jar$");

    private final Instrumentation inst;
    private final File raspHome;
    private final File outFile;
    private final Function<String, Boolean> uploader;
    private final long initialDelayMs;
    private final long intervalMs;
    private volatile boolean running;
    private volatile boolean forceReport;
    private Thread thread;
    private final Map<String, List<Map<String, Object>>> cache = new LinkedHashMap<>();

    /**
     * @param uploader posts the JSON body to the server and returns true on success; returns null
     *                 when the agent is not (yet) connected.
     */
    public DependencyScanner(Instrumentation inst, File raspHome, Function<String, Boolean> uploader,
                             long initialDelayMs, long intervalMs) {
        this.inst = inst;
        this.raspHome = raspHome.getAbsoluteFile();
        this.outFile = new File(raspHome, "logs/dependencies.json");
        this.uploader = uploader;
        this.initialDelayMs = initialDelayMs;
        this.intervalMs = intervalMs;
    }

    /** Ask for an upload on the next round even if nothing changed (e.g. after re-registration). */
    public void requestReport() {
        forceReport = true;
    }

    public synchronized void start() {
        running = true;
        thread = new Thread(this::loop, "zhuwei-rasp-scanner");
        thread.setDaemon(true);
        thread.setPriority(Thread.MIN_PRIORITY);
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
        String lastFingerprint = "";
        boolean uploaded = false;
        long wait = initialDelayMs;
        while (running) {
            try {
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                return;
            }
            wait = intervalMs;
            try {
                long t0 = System.currentTimeMillis();
                List<Map<String, Object>> items = scan();
                String fp = fingerprint(items);
                boolean changed = !fp.equals(lastFingerprint);
                if (changed) {
                    writeLocal(items);
                    RaspLog.info("dependency scan: " + items.size() + " components in "
                            + (System.currentTimeMillis() - t0) + "ms");
                }
                if (changed || forceReport || !uploaded) {
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("items", items);
                    Boolean ok = uploader.apply(Json.stringify(body));
                    if (ok != null) {
                        uploaded = ok;
                        if (ok) {
                            forceReport = false;
                        }
                    }
                }
                lastFingerprint = fp;
            } catch (Throwable t) {
                RaspLog.warn("dependency scan failed", t);
            }
        }
    }

    /** Collects components from the code sources of all loaded classes. */
    List<Map<String, Object>> scan() {
        Set<String> locations = new LinkedHashSet<>();
        for (Class<?> c : inst.getAllLoadedClasses()) {
            try {
                if (c.getClassLoader() == null) {
                    continue;
                }
                CodeSource cs = c.getProtectionDomain().getCodeSource();
                if (cs != null && cs.getLocation() != null) {
                    locations.add(cs.getLocation().toString());
                }
            } catch (Throwable ignore) {
                // some classes refuse inspection
            }
        }
        if (RaspLog.isDebug()) {
            RaspLog.debug("dependency scan: " + locations.size() + " code source locations " + locations);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> seenJars = new LinkedHashSet<>();
        for (String loc : locations) {
            JarLocation j = JarLocation.parse(loc);
            if (j == null || isOwnJar(j) || !seenJars.add(j.display())) {
                continue;
            }
            List<Map<String, Object>> items = cache.get(j.display());
            if (items == null) {
                items = inspect(j);
                cache.put(j.display(), items);
            }
            out.addAll(items);
            if (out.size() >= MAX_ITEMS) {
                RaspLog.warn("dependency scan truncated at " + MAX_ITEMS + " components");
                break;
            }
        }
        return out;
    }

    private boolean isOwnJar(JarLocation j) {
        File parent = j.outer.getAbsoluteFile().getParentFile();
        return parent != null && parent.equals(raspHome);
    }

    private List<Map<String, Object>> inspect(JarLocation j) {
        try {
            if (j.nested == null) {
                try (JarFile jf = new JarFile(j.outer)) {
                    String sha1 = sha1(Files.newInputStream(j.outer.toPath()));
                    List<Properties> poms = new ArrayList<>();
                    Enumeration<JarEntry> en = jf.entries();
                    while (en.hasMoreElements()) {
                        JarEntry e = en.nextElement();
                        if (isPom(e.getName())) {
                            try (InputStream in = jf.getInputStream(e)) {
                                poms.add(load(in));
                            }
                        }
                    }
                    return items(j, sha1, poms, jf.getManifest());
                }
            }
            try (JarFile outer = new JarFile(j.outer)) {
                JarEntry entry = outer.getJarEntry(j.nested);
                if (entry == null || entry.getSize() > MAX_NESTED_BYTES) {
                    return fallback(j, null);
                }
                byte[] bytes;
                try (InputStream in = outer.getInputStream(entry)) {
                    bytes = readAll(in);
                }
                List<Properties> poms = new ArrayList<>();
                Manifest mf;
                try (JarInputStream jin = new JarInputStream(new ByteArrayInputStream(bytes))) {
                    mf = jin.getManifest();
                    JarEntry e;
                    while ((e = jin.getNextJarEntry()) != null) {
                        if (isPom(e.getName())) {
                            poms.add(load(jin));
                        }
                    }
                }
                return items(j, sha1(new ByteArrayInputStream(bytes)), poms, mf);
            }
        } catch (Exception e) {
            RaspLog.debug("cannot inspect " + j.display() + ": " + e);
            return fallback(j, null);
        }
    }

    private List<Map<String, Object>> items(JarLocation j, String sha1, List<Properties> poms, Manifest mf) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Properties p : poms) {
            String g = p.getProperty("groupId");
            String a = p.getProperty("artifactId");
            String v = p.getProperty("version");
            if (a != null && v != null) {
                out.add(item(j, sha1, g, a, v, poms.size() > 1 ? "pom-shaded" : "pom"));
            }
        }
        if (!out.isEmpty()) {
            return out;
        }
        if (mf != null) {
            Attributes at = mf.getMainAttributes();
            String a = first(at.getValue("Bundle-SymbolicName"), at.getValue("Implementation-Title"),
                    at.getValue("Automatic-Module-Name"));
            String v = first(at.getValue("Bundle-Version"), at.getValue("Implementation-Version"));
            if (a != null && v != null) {
                int semi = a.indexOf(';');
                String name = semi > 0 ? a.substring(0, semi) : a;
                // Prefer the familiar file-name artifact (h2, tomcat-embed-core) over OSGi symbolic names
                // (com.h2database) when the file name carries the same version.
                Matcher fm = FILE_VERSION.matcher(j.fileName());
                if (fm.matches() && fm.group(2).equals(v)) {
                    name = fm.group(1);
                }
                out.add(item(j, sha1, at.getValue("Implementation-Vendor-Id"), name, v, "manifest"));
                return out;
            }
        }
        return fallback(j, sha1);
    }

    private List<Map<String, Object>> fallback(JarLocation j, String sha1) {
        List<Map<String, Object>> out = new ArrayList<>();
        Matcher m = FILE_VERSION.matcher(j.fileName());
        if (m.matches()) {
            out.add(item(j, sha1, null, m.group(1), m.group(2), "filename"));
        } else {
            out.add(item(j, sha1, null, j.fileName().replaceAll("\\.jar$", ""), "", "filename"));
        }
        return out;
    }

    private static Map<String, Object> item(JarLocation j, String sha1, String g, String a, String v, String source) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("group", g == null ? "" : g.trim());
        m.put("artifact", a.trim());
        m.put("version", v == null ? "" : v.trim());
        m.put("file", j.fileName());
        m.put("path", j.display());
        m.put("sha1", sha1 == null ? "" : sha1);
        m.put("source", source);
        return m;
    }

    private static boolean isPom(String name) {
        return name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties");
    }

    private static Properties load(InputStream in) throws IOException {
        Properties p = new Properties();
        p.load(new java.io.InputStreamReader(new NonClosing(in), StandardCharsets.ISO_8859_1));
        return p;
    }

    private static String first(String... vs) {
        for (String v : vs) {
            if (v != null && !v.trim().isEmpty()) {
                return v.trim();
            }
        }
        return null;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            bo.write(buf, 0, n);
        }
        return bo.toByteArray();
    }

    private static String sha1(InputStream in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        try (InputStream s = in) {
            byte[] buf = new byte[16384];
            int n;
            while ((n = s.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest()) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    private static String fingerprint(List<Map<String, Object>> items) {
        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> m : items) {
            sb.append(m.get("path")).append('|').append(m.get("artifact")).append('|').append(m.get("version")).append('\n');
        }
        return Integer.toHexString(sb.toString().hashCode()) + ":" + items.size();
    }

    private void writeLocal(List<Map<String, Object>> items) {
        try {
            outFile.getParentFile().mkdirs();
            Files.write(outFile.toPath(), Json.stringify(items).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            RaspLog.warn("cannot write " + outFile + ": " + e);
        }
    }

    /** Prevents Properties.load from closing the shared JarInputStream. */
    private static final class NonClosing extends java.io.FilterInputStream {
        NonClosing(InputStream in) {
            super(in);
        }

        @Override
        public void close() {
            // keep the underlying stream open
        }
    }
}
