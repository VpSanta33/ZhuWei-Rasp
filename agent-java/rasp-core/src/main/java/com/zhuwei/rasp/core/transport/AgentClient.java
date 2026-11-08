package com.zhuwei.rasp.core.transport;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HTTPS client for the agent API (docs chapter 7). Every request is signed:
 * <pre>
 * X-Rasp-Sign = hex(HMAC-SHA256(app_secret, METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(SHA256(body))))
 * </pre>
 */
public final class AgentClient {

    public static final class Response {
        public final int status;
        public final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    private final String baseUrl;
    private final String appKey;
    private final byte[] appSecret;
    private volatile String agentId = "";

    public AgentClient(String baseUrl, String appKey, String appSecret) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.appKey = appKey;
        this.appSecret = appSecret.getBytes(StandardCharsets.UTF_8);
    }

    public void setAgentId(String id) {
        this.agentId = id;
    }

    public Response get(String path) throws IOException {
        return send("GET", path, new byte[0]);
    }

    public Response post(String path, String json) throws IOException {
        return send("POST", path, json.getBytes(StandardCharsets.UTF_8));
    }

    private Response send(String method, String path, byte[] body) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        try {
            c.setConnectTimeout(3000);
            c.setReadTimeout(5000);
            c.setRequestMethod(method);
            c.setUseCaches(false);
            String ts = String.valueOf(System.currentTimeMillis());
            String nonce = UUID.randomUUID().toString().replace("-", "");
            String signPath = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            c.setRequestProperty("X-Rasp-AppKey", appKey);
            c.setRequestProperty("X-Rasp-AgentId", agentId);
            c.setRequestProperty("X-Rasp-Timestamp", ts);
            c.setRequestProperty("X-Rasp-Nonce", nonce);
            c.setRequestProperty("X-Rasp-Sign", sign(method, signPath, ts, nonce, body));
            if (body.length > 0) {
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json;charset=UTF-8");
                try (OutputStream os = c.getOutputStream()) {
                    os.write(body);
                }
            }
            int status = c.getResponseCode();
            InputStream in = status >= 400 ? c.getErrorStream() : c.getInputStream();
            return new Response(status, in == null ? "" : readAll(in));
        } finally {
            c.disconnect();
        }
    }

    String sign(String method, String path, String ts, String nonce, byte[] body) {
        try {
            String canonical = method + "\n" + path + "\n" + ts + "\n" + nonce + "\n"
                    + hex(MessageDigest.getInstance("SHA-256").digest(body));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(appSecret, "HmacSHA256"));
            return hex(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    private static String readAll(InputStream in) throws IOException {
        try (InputStream s = in) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = s.read(buf)) > 0) {
                bo.write(buf, 0, n);
            }
            return new String(bo.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
