package com.zhuwei.rasp.core.sca;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DependencyScannerTest {

    @TempDir
    File tmp;

    private static void jar(File f, Manifest mf, String... entries) throws IOException {
        try (JarOutputStream out = mf == null ? new JarOutputStream(new FileOutputStream(f)) : new JarOutputStream(new FileOutputStream(f), mf)) {
            for (int i = 0; i + 1 < entries.length; i += 2) {
                out.putNextEntry(new JarEntry(entries[i]));
                out.write(entries[i + 1].getBytes(StandardCharsets.ISO_8859_1));
                out.closeEntry();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> inspect(File f) throws Exception {
        DependencyScanner s = new DependencyScanner(null, tmp, x -> null, 0, 60_000);
        Method m = DependencyScanner.class.getDeclaredMethod("inspect", JarLocation.class);
        m.setAccessible(true);
        return (List<Map<String, Object>>) m.invoke(s, JarLocation.parse(f.toURI().toString()));
    }

    @Test
    void pomPropertiesWin() throws Exception {
        File f = new File(tmp, "whatever.jar");
        jar(f, null, "META-INF/maven/org.x/lib-a/pom.properties", "groupId=org.x\nartifactId=lib-a\nversion=1.2.3\n");
        Map<String, Object> it = inspect(f).get(0);
        assertEquals("org.x", it.get("group"));
        assertEquals("lib-a", it.get("artifact"));
        assertEquals("1.2.3", it.get("version"));
        assertEquals("pom", it.get("source"));
        assertEquals(40, ((String) it.get("sha1")).length());
    }

    @Test
    void shadedJarListsEveryBundledPom() throws Exception {
        File f = new File(tmp, "app-all.jar");
        jar(f, null,
                "META-INF/maven/org.x/a/pom.properties", "groupId=org.x\nartifactId=a\nversion=1\n",
                "META-INF/maven/org.y/b/pom.properties", "groupId=org.y\nartifactId=b\nversion=2\n");
        List<Map<String, Object>> items = inspect(f);
        assertEquals(2, items.size());
        assertEquals("pom-shaded", items.get(0).get("source"));
    }

    @Test
    void manifestUsesFileNameArtifactWhenVersionsAgree() throws Exception {
        Manifest mf = new Manifest();
        mf.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        mf.getMainAttributes().putValue("Bundle-SymbolicName", "com.h2database");
        mf.getMainAttributes().putValue("Bundle-Version", "2.3.232");
        File f = new File(tmp, "h2-2.3.232.jar");
        jar(f, mf, "org/h2/Driver.class", "x");
        Map<String, Object> it = inspect(f).get(0);
        assertEquals("h2", it.get("artifact"));
        assertEquals("2.3.232", it.get("version"));
        assertEquals("manifest", it.get("source"));
    }

    @Test
    void fileNameFallback() throws Exception {
        File f = new File(tmp, "legacy-lib-4.0.1-RELEASE.jar");
        jar(f, null, "a/B.class", "x");
        Map<String, Object> it = inspect(f).get(0);
        assertEquals("legacy-lib", it.get("artifact"));
        assertEquals("4.0.1-RELEASE", it.get("version"));
        assertEquals("filename", it.get("source"));
    }

    @Test
    void nestedSpringBootJar() throws Exception {
        File inner = new File(tmp, "inner.jar");
        jar(inner, null, "META-INF/maven/org.z/c/pom.properties", "groupId=org.z\nartifactId=c\nversion=9.9\n");
        byte[] innerBytes = java.nio.file.Files.readAllBytes(inner.toPath());
        File outer = new File(tmp, "boot.jar");
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(outer))) {
            out.putNextEntry(new JarEntry("BOOT-INF/lib/c-9.9.jar"));
            out.write(innerBytes);
            out.closeEntry();
        }
        DependencyScanner s = new DependencyScanner(null, tmp, x -> null, 0, 60_000);
        Method m = DependencyScanner.class.getDeclaredMethod("inspect", JarLocation.class);
        m.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) m.invoke(s,
                JarLocation.parse("jar:nested:" + outer.getPath() + "/!BOOT-INF/lib/c-9.9.jar!/"));
        assertEquals("c", items.get(0).get("artifact"));
        assertEquals("9.9", items.get(0).get("version"));
        assertEquals(outer.getPath() + "!/BOOT-INF/lib/c-9.9.jar", items.get(0).get("path"));
    }
}
