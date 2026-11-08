package com.zhuwei.rasp.core.sca;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class JarLocationTest {

    @Test
    void plainJar() {
        JarLocation j = JarLocation.parse("file:/opt/app/lib/commons-io-2.16.1.jar");
        assertEquals("/opt/app/lib/commons-io-2.16.1.jar", j.outer.getPath());
        assertNull(j.nested);
        assertEquals("commons-io-2.16.1.jar", j.fileName());
    }

    @Test
    void springBootLegacyNested() {
        JarLocation j = JarLocation.parse("jar:file:/opt/app.jar!/BOOT-INF/lib/jackson-core-2.17.0.jar!/");
        assertEquals("/opt/app.jar", j.outer.getPath());
        assertEquals("BOOT-INF/lib/jackson-core-2.17.0.jar", j.nested);
        assertEquals("/opt/app.jar!/BOOT-INF/lib/jackson-core-2.17.0.jar", j.display());
    }

    @Test
    void springBoot32Nested() {
        JarLocation j = JarLocation.parse("jar:nested:/opt/my%20app.jar/!BOOT-INF/lib/snakeyaml-2.2.jar!/");
        assertEquals("/opt/my app.jar", j.outer.getPath());
        assertEquals("BOOT-INF/lib/snakeyaml-2.2.jar", j.nested);
    }

    @Test
    void ignoresDirectoriesAndClassesFolders() {
        assertNull(JarLocation.parse("file:/opt/app/WEB-INF/classes/"));
        assertNull(JarLocation.parse("jar:file:/opt/app.jar!/BOOT-INF/classes!/"));
        assertNull(JarLocation.parse("jrt:/java.base"));
        assertNull(JarLocation.parse(null));
    }
}
