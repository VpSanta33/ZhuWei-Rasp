package com.zhuwei.rasp.core.context;

import com.zhuwei.rasp.core.util.Json;
import com.zhuwei.rasp.core.util.Reflect;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Per-request state, stored in a ThreadLocal by {@link ContextHolder}.
 *
 * <p>Request data is read lazily and only through side-effect free accessors. The body is never read
 * by the agent: {@link #appendBody} receives a copy of what the application itself reads from the
 * ServletInputStream.</p>
 *
 * <p>{@link #snapshotForAsync()} creates a detached copy (no reference to the servlet request, which the
 * container recycles) used to carry the context into thread-pool tasks.</p>
 */
public final class RequestContext {

    private static final int MAX_INPUTS = 512;
    private static final int MAX_INPUT_LEN = 4096;
    private static final int MAX_JSON_DEPTH = 32;
    private static final String[] HEADERS_FOR_REPORT = {
            "host", "user-agent", "referer", "content-type", "accept", "x-forwarded-for", "x-real-ip", "cookie", "authorization",
    };

    public final String requestId;
    public final long startNanos = System.nanoTime();
    public final Object request;
    public final Object response;
    /** true for a detached copy running in a thread-pool task. */
    public final boolean async;
    /** Servlet.service nesting depth (forward/include). Only the outermost call owns the context. */
    public int depth;
    public volatile boolean blocked;
    public volatile boolean blockPageWritten;
    public String blockType;
    public int checkCount;

    private final boolean readFormParams;
    private final int bodyMax;
    private String method;
    private String uri;
    private String url;
    private String queryString;
    private String remoteAddr;
    private Map<String, String> headers; // only filled for snapshots
    private Map<String, List<String>> params;
    private List<String> userInputs;
    private int userInputsBodyLen = -1;

    // body capture
    private byte[] body = new byte[0];
    private int bodyLen;
    private Object bodyStream;
    private boolean bodyTruncated;
    private Map<String, List<String>> bodyParams;
    private int bodyParamsLen = -1;

    public RequestContext(Object request, Object response, boolean readFormParams, int bodyMax) {
        this.requestId = UUID.randomUUID().toString();
        this.request = request;
        this.response = response;
        this.readFormParams = readFormParams;
        this.bodyMax = Math.max(0, bodyMax);
        this.async = false;
    }

    private RequestContext(RequestContext src) {
        this.requestId = src.requestId;
        this.request = null;
        this.response = null;
        this.async = true;
        this.readFormParams = false;
        this.bodyMax = 0;
        this.method = src.method();
        this.uri = src.uri();
        this.url = src.url();
        this.queryString = src.queryString();
        this.remoteAddr = src.remoteAddr();
        Map<String, String> h = new LinkedHashMap<>();
        for (String n : HEADERS_FOR_REPORT) {
            String v = src.header(n);
            if (!v.isEmpty()) {
                h.put(n, v);
            }
        }
        this.headers = Collections.unmodifiableMap(h);
        this.params = src.params();
        this.bodyParams = src.bodyParams();
        this.bodyParamsLen = 0;
        this.userInputs = Collections.unmodifiableList(new ArrayList<>(src.userInputs()));
        this.userInputsBodyLen = 0;
    }

    /** Detached, immutable-ish copy for use on another thread after the request may have finished. */
    public RequestContext snapshotForAsync() {
        return async ? this : new RequestContext(this);
    }

    // ------------------------------------------------------------------ request line & headers

    public String method() {
        if (method == null) {
            method = str(Reflect.call(request, "getMethod"));
        }
        return method;
    }

    public String uri() {
        if (uri == null) {
            uri = str(Reflect.call(request, "getRequestURI"));
        }
        return uri;
    }

    public String url() {
        if (url == null) {
            Object u = Reflect.call(request, "getRequestURL");
            String q = queryString();
            String base = u == null ? uri() : u.toString();
            url = q.isEmpty() ? base : base + "?" + q;
        }
        return url;
    }

    public String queryString() {
        if (queryString == null) {
            queryString = str(Reflect.call(request, "getQueryString"));
        }
        return queryString;
    }

    public String remoteAddr() {
        if (remoteAddr == null) {
            remoteAddr = str(Reflect.call(request, "getRemoteAddr"));
        }
        return remoteAddr;
    }

    public String header(String name) {
        if (headers != null) {
            String v = headers.get(name.toLowerCase(Locale.ROOT));
            return v == null ? "" : v;
        }
        return str(Reflect.call(request, "getHeader", new Class<?>[]{String.class}, name));
    }

    public Map<String, String> reportHeaders() {
        if (headers != null) {
            return headers;
        }
        Map<String, String> h = new LinkedHashMap<>();
        for (String n : HEADERS_FOR_REPORT) {
            String v = header(n);
            if (!v.isEmpty()) {
                h.put(n, v);
            }
        }
        return h;
    }

    // ------------------------------------------------------------------ parameters

    /**
     * Query-string parameters (parsed by the agent itself). Form bodies come from the captured body
     * ({@link #bodyParams()}), or from getParameterMap when {@code read_form_params} is enabled.
     */
    @SuppressWarnings("unchecked")
    public Map<String, List<String>> params() {
        if (params != null) {
            return params;
        }
        Map<String, List<String>> p = new LinkedHashMap<>();
        parseQuery(queryString(), p);
        if (readFormParams) {
            Object m = Reflect.call(request, "getParameterMap");
            if (m instanceof Map) {
                for (Map.Entry<Object, Object> e : ((Map<Object, Object>) m).entrySet()) {
                    List<String> vals = p.computeIfAbsent(String.valueOf(e.getKey()), k -> new ArrayList<>());
                    if (e.getValue() instanceof String[]) {
                        for (String v : (String[]) e.getValue()) {
                            if (!vals.contains(v)) {
                                vals.add(v);
                            }
                        }
                    }
                }
            }
        }
        params = p;
        return p;
    }

    // ------------------------------------------------------------------ body

    /**
     * Copies bytes the application has just read from {@code stream}. Only the first stream that
     * delivers data is recorded, so wrapper streams delegating to the container stream are not counted twice.
     */
    public void appendBody(Object stream, byte[] buf, int off, int n) {
        if (bodyMax == 0 || n <= 0 || buf == null || off < 0 || off + n > buf.length) {
            return;
        }
        if (bodyStream == null) {
            bodyStream = stream;
        } else if (bodyStream != stream) {
            return;
        }
        int room = bodyMax - bodyLen;
        if (room <= 0) {
            bodyTruncated = true;
            return;
        }
        int take = Math.min(room, n);
        if (bodyLen + take > body.length) {
            byte[] nb = new byte[Math.min(bodyMax, Math.max(body.length * 2, bodyLen + take))];
            System.arraycopy(body, 0, nb, 0, bodyLen);
            body = nb;
        }
        System.arraycopy(buf, off, body, bodyLen, take);
        bodyLen += take;
        if (take < n) {
            bodyTruncated = true;
        }
    }

    public int bodyLength() {
        return bodyLen;
    }

    public boolean bodyTruncated() {
        return bodyTruncated;
    }

    /** Parameters parsed from the captured body: JSON leaves (key path -&gt; values) or urlencoded form. */
    public Map<String, List<String>> bodyParams() {
        if (bodyParams != null && bodyParamsLen == (async ? 0 : bodyLen)) {
            return bodyParams;
        }
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (bodyLen > 0) {
            String ct = header("content-type").toLowerCase(Locale.ROOT);
            String text = new String(body, 0, bodyLen, charset(ct));
            if (ct.contains("json")) {
                parseJsonBody(text, out);
            } else if (ct.contains("application/x-www-form-urlencoded")) {
                parseQuery(text, out);
            } else if (ct.startsWith("multipart/")) {
                parseMultipartNames(text, out);
            }
        }
        bodyParams = out;
        bodyParamsLen = bodyLen;
        return out;
    }

    private static void parseJsonBody(String text, Map<String, List<String>> out) {
        Object root;
        try {
            root = Json.parse(text.trim());
        } catch (RuntimeException e) {
            return; // truncated or not JSON: ignore rather than guess
        }
        flatten("", root, out, 0);
    }

    private static void flatten(String path, Object v, Map<String, List<String>> out, int depth) {
        if (depth > MAX_JSON_DEPTH || out.size() >= MAX_INPUTS) {
            return;
        }
        if (v instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                String k = String.valueOf(e.getKey());
                out.computeIfAbsent("$key", x -> new ArrayList<>()).add(k);
                flatten(path.isEmpty() ? k : path + "." + k, e.getValue(), out, depth + 1);
            }
        } else if (v instanceof Collection) {
            for (Object o : (Collection<?>) v) {
                flatten(path + "[]", o, out, depth + 1);
            }
        } else if (v != null) {
            out.computeIfAbsent(path.isEmpty() ? "$root" : path, x -> new ArrayList<>()).add(String.valueOf(v));
        }
    }

    /** Field names and file names of multipart parts (part contents are not used as inputs). */
    private static void parseMultipartNames(String text, Map<String, List<String>> out) {
        int i = 0;
        while ((i = text.indexOf("Content-Disposition:", i)) >= 0 && out.size() < MAX_INPUTS) {
            int end = text.indexOf('\n', i);
            String line = end < 0 ? text.substring(i) : text.substring(i, end);
            String name = attr(line, "name");
            String file = attr(line, "filename");
            if (file != null) {
                out.computeIfAbsent(name == null ? "$file" : name, x -> new ArrayList<>()).add(file);
            }
            i = end < 0 ? text.length() : end;
        }
    }

    private static String attr(String line, String key) {
        String k = " " + key + "=\"";
        int s = line.indexOf(k);
        if (s < 0) {
            k = ";" + key + "=\"";
            s = line.indexOf(k);
        }
        if (s < 0) {
            return null;
        }
        int e = line.indexOf('"', s + k.length());
        return e < 0 ? null : line.substring(s + k.length(), e);
    }

    private static Charset charset(String ct) {
        int i = ct.indexOf("charset=");
        if (i >= 0) {
            String cs = ct.substring(i + 8).split("[;\\s]")[0].replace("\"", "");
            try {
                return Charset.forName(cs);
            } catch (Exception ignore) {
                // fall through
            }
        }
        return StandardCharsets.UTF_8;
    }

    // ------------------------------------------------------------------ user inputs

    /** All user-controlled values (parameter names/values, body values, selected headers), de-duplicated. */
    public List<String> userInputs() {
        if (userInputs != null && userInputsBodyLen == (async ? 0 : bodyLen)) {
            return userInputs;
        }
        List<String> in = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : params().entrySet()) {
            addInput(in, e.getKey());
            for (String v : e.getValue()) {
                addInput(in, v);
            }
        }
        for (Map.Entry<String, List<String>> e : bodyParams().entrySet()) {
            if (!e.getKey().startsWith("$")) {
                addInput(in, lastSegment(e.getKey())); // form field name / JSON key ($key holds all JSON keys)
            }
            for (String v : e.getValue()) {
                addInput(in, v);
            }
        }
        Object names = Reflect.call(request, "getHeaderNames");
        if (names instanceof Enumeration) {
            for (Object n : Collections.list((Enumeration<?>) names)) {
                String hn = String.valueOf(n).toLowerCase(Locale.ROOT);
                if (hn.equals("referer") || hn.equals("user-agent") || hn.startsWith("x-")) {
                    addInput(in, header(hn));
                }
            }
        }
        userInputs = in;
        userInputsBodyLen = bodyLen;
        return in;
    }

    private static String lastSegment(String path) {
        String p = path.endsWith("[]") ? path.substring(0, path.length() - 2) : path;
        int i = p.lastIndexOf('.');
        return i >= 0 ? p.substring(i + 1) : p;
    }

    private static void addInput(List<String> in, String v) {
        if (v == null || v.isEmpty() || in.size() >= MAX_INPUTS) {
            return;
        }
        String s = v.length() > MAX_INPUT_LEN ? v.substring(0, MAX_INPUT_LEN) : v;
        if (!in.contains(s)) {
            in.add(s);
        }
    }

    static void parseQuery(String q, Map<String, List<String>> out) {
        if (q == null || q.isEmpty()) {
            return;
        }
        for (String pair : q.split("&")) {
            if (pair.isEmpty() || out.size() >= MAX_INPUTS) {
                continue;
            }
            int i = pair.indexOf('=');
            String k = decode(i < 0 ? pair : pair.substring(0, i));
            String v = i < 0 ? "" : decode(pair.substring(i + 1));
            out.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
        }
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString();
    }
}
