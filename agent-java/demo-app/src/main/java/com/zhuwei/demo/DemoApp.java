package com.zhuwei.demo;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Minimal web app whose endpoints pass request parameters into the sinks the agent hooks
 * (file read, outbound HTTP, JDBC, process). It exists to verify hooks, context propagation,
 * alarm reporting and blocking end to end. Run it in an isolated test environment only.
 *
 * <pre>
 * java -javaagent:dist/rasp/rasp-launcher.jar -jar demo-app.jar [port]
 * </pre>
 */
public final class DemoApp {

    private static Connection db;
    private static File dataDir;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8088;
        dataDir = Files.createTempDirectory("rasp-demo").toFile();
        Files.write(new File(dataDir, "readme.txt").toPath(), "hello from demo data\n".getBytes(StandardCharsets.UTF_8));

        db = DriverManager.getConnection("jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1");
        try (Statement st = db.createStatement()) {
            st.execute("create table users(id int primary key, name varchar(64))");
            st.execute("insert into users values (1,'alice'),(2,'bob')");
        }

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(port);
        tomcat.setBaseDir(Files.createTempDirectory("rasp-demo-tomcat").toString());
        tomcat.getConnector();
        Context ctx = tomcat.addContext("", null);
        servlet(tomcat, ctx, "hello", "/hello", (req, resp) -> resp.getWriter().write("ok\n"));
        servlet(tomcat, ctx, "file", "/file", DemoApp::file);
        servlet(tomcat, ctx, "user", "/user", DemoApp::user);
        servlet(tomcat, ctx, "fetch", "/fetch", DemoApp::fetch);
        servlet(tomcat, ctx, "exec", "/exec", DemoApp::exec);
        servlet(tomcat, ctx, "json", "/json", DemoApp::json);
        servlet(tomcat, ctx, "async", "/async", DemoApp::async);
        tomcat.start();
        System.out.println("demo app listening on http://127.0.0.1:" + port);
        tomcat.getServer().await();
    }

    /** GET /file?name=readme.txt */
    private static void file(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        File f = new File(dataDir, req.getParameter("name"));
        try (InputStream in = new FileInputStream(f)) {
            resp.getWriter().write(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** GET /user?id=1  (string-concatenated SQL on purpose) */
    private static void user(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        try (Statement st = db.createStatement();
             ResultSet rs = st.executeQuery("select name from users where id = " + req.getParameter("id"))) {
            StringBuilder sb = new StringBuilder();
            while (rs.next()) {
                sb.append(rs.getString(1)).append('\n');
            }
            resp.getWriter().write(sb.toString());
        }
    }

    /** GET /fetch?url=http://127.0.0.1:8088/hello */
    private static void fetch(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(req.getParameter("url")).openConnection();
        c.setConnectTimeout(2000);
        c.setReadTimeout(2000);
        try (InputStream in = c.getInputStream()) {
            resp.getWriter().write("fetched " + in.readAllBytes().length + " bytes\n");
        }
    }

    /** GET /exec?arg=hello  (runs echo with an argument array, no shell) */
    private static void exec(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        Process p = new ProcessBuilder("echo", req.getParameter("arg")).start();
        resp.getWriter().write(new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        p.waitFor();
    }

    private static final java.util.concurrent.ExecutorService POOL = java.util.concurrent.Executors.newFixedThreadPool(2);

    /** POST /json  body {"name":"readme.txt"}  (reads the body with a naive parser, like any JSON library would) */
    private static void json(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String body = new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"name\"\\s*:\\s*\"([^\"]*)\"").matcher(body);
        if (!m.find()) {
            resp.setStatus(400);
            resp.getWriter().write("need {\"name\":...}\n");
            return;
        }
        try (InputStream in = new FileInputStream(new File(dataDir, m.group(1)))) {
            resp.getWriter().write(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** GET /async?name=readme.txt  (file is read on a thread-pool worker, not the request thread) */
    private static void async(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("name");
        java.util.concurrent.Future<String> f = POOL.submit(() -> {
            try (InputStream in = new FileInputStream(new File(dataDir, name))) {
                return Thread.currentThread().getName() + ": " + new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        });
        try {
            resp.getWriter().write(f.get());
        } catch (java.util.concurrent.ExecutionException e) {
            resp.setStatus(e.getCause() instanceof SecurityException ? 403 : 500);
            resp.getWriter().write("task failed: " + e.getCause() + "\n");
        }
    }

    interface Handler {
        void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception;
    }

    private static void servlet(Tomcat t, Context ctx, String name, String path, Handler h) {
        t.addServlet(ctx, name, new HttpServlet() {
            @Override
            protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                doGet(req, resp);
            }

            @Override
            protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
                resp.setContentType("text/plain;charset=UTF-8");
                try {
                    h.handle(req, resp);
                } catch (SecurityException e) {
                    throw e;
                } catch (Exception e) {
                    resp.setStatus(500);
                    resp.getWriter().write("error: " + e + "\n");
                }
            }
        });
        ctx.addServletMappingDecoded(path, name);
    }
}
