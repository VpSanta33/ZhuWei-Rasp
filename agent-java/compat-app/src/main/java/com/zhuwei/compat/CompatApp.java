package com.zhuwei.compat;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Minimal Java 8 servlet application (javax.servlet on Tomcat 9) for agent compatibility tests.
 * Each endpoint reads a file named by a request parameter, so the generic "user input reaches a file
 * path" rule produces an alarm on the request thread, in a thread pool and in a CompletableFuture.
 * For isolated test environments only.
 */
public final class CompatApp {

    private static final ExecutorService POOL = Executors.newFixedThreadPool(2);
    private static File dataDir;

    private CompatApp() { }

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 18098;
        File base = Files.createTempDirectory("compat-app").toFile();
        dataDir = new File(base, "data");
        dataDir.mkdirs();
        Files.write(new File(dataDir, "readme.txt").toPath(), "hello from compat app\n".getBytes(StandardCharsets.UTF_8));

        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(base.getAbsolutePath());
        tomcat.setPort(port);
        tomcat.getConnector();
        Context ctx = tomcat.addContext("", base.getAbsolutePath());
        servlet(tomcat, ctx, "hello", "/hello", (req, resp) -> resp.getWriter().write("ok java=" + System.getProperty("java.version") + "\n"));
        servlet(tomcat, ctx, "file", "/file", (req, resp) -> resp.getWriter().write(read(req.getParameter("name"))));
        servlet(tomcat, ctx, "exec", "/exec", (req, resp) -> { // fixed command; only the argument is echoed
            Process p = new ProcessBuilder("echo", req.getParameter("arg")).redirectErrorStream(true).start();
            p.waitFor();
            resp.getWriter().write("exit=" + p.exitValue() + "\n");
        });
        servlet(tomcat, ctx, "pool", "/pool", (req, resp) -> {
            String name = req.getParameter("name");
            Future<String> f = POOL.submit(() -> read(name));
            resp.getWriter().write(f.get());
        });
        servlet(tomcat, ctx, "cf", "/cf", (req, resp) -> {
            String name = req.getParameter("name");
            resp.getWriter().write(CompletableFuture.supplyAsync(() -> {
                try {
                    return read(name);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).join());
        });
        tomcat.start();
        System.out.println("compat app on http://127.0.0.1:" + port + " java=" + System.getProperty("java.version"));
        tomcat.getServer().await();
    }

    private static String read(String name) throws IOException {
        try (InputStream in = new FileInputStream(new File(dataDir, name))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return Thread.currentThread().getName() + ": " + new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    interface Handler {
        void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception;
    }

    private static void servlet(Tomcat t, Context ctx, String name, String path, Handler h) {
        t.addServlet(ctx, name, new HttpServlet() {
            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.setContentType("text/plain;charset=UTF-8");
                try {
                    h.handle(req, resp);
                } catch (SecurityException e) {
                    throw e; // blocked by the agent: let the block page through
                } catch (Exception e) {
                    Throwable c = e;
                    while (c.getCause() != null && !(c instanceof SecurityException)) {
                        c = c.getCause();
                    }
                    resp.setStatus(c instanceof SecurityException ? 403 : 500);
                    resp.getWriter().write("failed: " + c + "\n");
                }
            }
        });
        ctx.addServletMappingDecoded(path, name);
    }
}
