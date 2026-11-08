package com.zhuwei.rasp.core.sca;

import java.io.File;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Parsed code-source location of a jar. Supports:
 * <ul>
 *   <li>{@code file:/opt/app/lib/a.jar} (classpath, Tomcat WEB-INF/lib)</li>
 *   <li>{@code jar:file:/opt/app.jar!/BOOT-INF/lib/a.jar!/} (Spring Boot &lt;= 3.1)</li>
 *   <li>{@code jar:nested:/opt/app.jar/!BOOT-INF/lib/a.jar!/} (Spring Boot 3.2+)</li>
 * </ul>
 * Directories (exploded classes) and non-jar entries return null.
 */
final class JarLocation {

    final File outer;
    /** Entry name inside {@link #outer}, or null for a top-level jar. */
    final String nested;

    private JarLocation(File outer, String nested) {
        this.outer = outer;
        this.nested = nested;
    }

    String display() {
        return nested == null ? outer.getPath() : outer.getPath() + "!/" + nested;
    }

    String fileName() {
        String n = nested == null ? outer.getName() : nested;
        int i = n.lastIndexOf('/');
        return i >= 0 ? n.substring(i + 1) : n;
    }

    static JarLocation parse(String loc) {
        if (loc == null) {
            return null;
        }
        try {
            if (loc.startsWith("file:")) {
                if (!loc.endsWith(".jar")) {
                    return null;
                }
                return new JarLocation(new File(URI.create(loc)), null);
            }
            if (loc.startsWith("jar:nested:")) {
                String rest = loc.substring("jar:nested:".length());
                int sep = rest.indexOf("/!");
                if (sep < 0) {
                    return null;
                }
                String entry = strip(rest.substring(sep + 2));
                return entry.endsWith(".jar") ? new JarLocation(new File(decode(rest.substring(0, sep))), entry) : null;
            }
            if (loc.startsWith("jar:file:")) {
                String rest = loc.substring("jar:".length());
                int sep = rest.indexOf("!/");
                if (sep < 0) {
                    return null;
                }
                File outer = new File(URI.create(rest.substring(0, sep)));
                String entry = strip(rest.substring(sep + 2));
                if (entry.isEmpty()) {
                    return outer.getName().endsWith(".jar") ? new JarLocation(outer, null) : null;
                }
                return entry.endsWith(".jar") ? new JarLocation(outer, entry) : null;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }
        return null;
    }

    private static String strip(String s) {
        String r = s;
        while (r.endsWith("!/") || r.endsWith("/")) {
            r = r.endsWith("!/") ? r.substring(0, r.length() - 2) : r.substring(0, r.length() - 1);
        }
        return r;
    }

    private static String decode(String s) {
        return urlDecode(s.replace("+", "%2B"));
    }

    /** URLDecoder.decode(String, Charset) is JDK 10+; the charset-name overload exists since 1.4. */
    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return s; // UTF-8 is always supported
        }
    }
}
