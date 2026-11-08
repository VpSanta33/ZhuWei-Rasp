package com.zhuwei.rasp.launcher;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Reflective access to com.sun.tools.attach so the launcher compiles for Java 8. On JDK 9+ the API comes from
 * the jdk.attach module; on JDK 8 it lives in $JAVA_HOME/lib/tools.jar, which is loaded on demand (with
 * {@code java -jar} the class path cannot be extended from the command line).
 */
final class AttachApi {

    /** Wraps checked attach exceptions so callers can tell "cannot attach" from "agent failed to load". */
    static final class AttachException extends Exception {
        final String kind; // simple class name of the original exception

        AttachException(Throwable cause) {
            super(cause.getMessage(), cause);
            this.kind = cause.getClass().getSimpleName();
        }
    }

    private static Class<?> vmClass;

    private AttachApi() { }

    static synchronized Class<?> vmClass() throws ClassNotFoundException {
        if (vmClass != null) {
            return vmClass;
        }
        try {
            vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        } catch (ClassNotFoundException e) {
            File home = new File(System.getProperty("java.home"));
            for (File tools : new File[]{new File(home, "../lib/tools.jar"), new File(home, "lib/tools.jar")}) {
                if (tools.isFile()) {
                    try {
                        URLClassLoader cl = new URLClassLoader(new URL[]{tools.toURI().toURL()}, AttachApi.class.getClassLoader());
                        vmClass = Class.forName("com.sun.tools.attach.VirtualMachine", true, cl);
                        return vmClass;
                    } catch (Exception ignore) {
                        // try the next location
                    }
                }
            }
            throw e;
        }
        return vmClass;
    }

    private static Object call(Object target, String method, Class<?>[] types, Object... args) throws AttachException {
        try {
            Class<?> c = target instanceof Class ? (Class<?>) target : target.getClass();
            Method m = (target instanceof Class ? c : vmClass()).getMethod(method, types);
            return m.invoke(target instanceof Class ? null : target, args);
        } catch (InvocationTargetException e) {
            throw new AttachException(e.getCause());
        } catch (Exception e) {
            throw new AttachException(e);
        }
    }

    /** Running JVMs as {pid, display name}. */
    static List<String[]> list() throws Exception {
        List<String[]> out = new ArrayList<>();
        for (Object d : (List<?>) call(vmClass(), "list", new Class<?>[0])) {
            String id = (String) d.getClass().getMethod("id").invoke(d);
            String name = (String) d.getClass().getMethod("displayName").invoke(d);
            out.add(new String[]{id, name});
        }
        return out;
    }

    /** An attached VM handle. */
    static final class Vm implements AutoCloseable {
        private final Object vm;

        Vm(String pid) throws Exception {
            this.vm = call(vmClass(), "attach", new Class<?>[]{String.class}, pid);
        }

        Properties systemProperties() throws AttachException {
            return (Properties) call(vm, "getSystemProperties", new Class<?>[0]);
        }

        void loadAgent(String jar, String args) throws AttachException {
            call(vm, "loadAgent", new Class<?>[]{String.class, String.class}, jar, args);
        }

        @Override
        public void close() {
            try {
                call(vm, "detach", new Class<?>[0]);
            } catch (AttachException ignore) {
                // best effort
            }
        }
    }
}
