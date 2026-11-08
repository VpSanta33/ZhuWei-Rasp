package com.zhuwei.rasp.core;

import com.zhuwei.rasp.core.context.AsyncContexts;
import com.zhuwei.rasp.core.context.ContextHolder;
import com.zhuwei.rasp.core.context.RequestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestContextTest {

    /** Minimal stand-in for a servlet request (accessed reflectively by RequestContext). */
    public static final class FakeRequest {
        private final Map<String, String> headers = new HashMap<>();
        private final String query;

        FakeRequest(String contentType, String query) {
            headers.put("content-type", contentType);
            this.query = query;
        }

        public String getHeader(String n) { return headers.get(n.toLowerCase()); }
        public Enumeration<String> getHeaderNames() { return Collections.enumeration(headers.keySet()); }
        public String getQueryString() { return query; }
        public String getMethod() { return "POST"; }
        public String getRequestURI() { return "/api"; }
        public StringBuffer getRequestURL() { return new StringBuffer("http://h/api"); }
        public String getRemoteAddr() { return "10.0.0.1"; }
    }

    @AfterEach
    void cleanup() {
        ContextHolder.clear();
    }

    private static RequestContext ctx(String ct, String query, String body, int max) {
        RequestContext c = new RequestContext(new FakeRequest(ct, query), null, false, max);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        Object stream = new Object();
        // delivered in two chunks, like a real read loop
        c.appendBody(stream, b, 0, Math.min(5, b.length));
        if (b.length > 5) {
            c.appendBody(stream, b, 5, b.length - 5);
        }
        return c;
    }

    @Test
    void jsonBodyBecomesUserInput() {
        RequestContext c = ctx("application/json;charset=UTF-8", "a=1",
                "{\"user\":{\"name\":\"alice-file.txt\",\"tags\":[\"x1\",\"y2\"]},\"n\":42}", 65536);
        Map<String, List<String>> bp = c.bodyParams();
        assertEquals(List.of("alice-file.txt"), bp.get("user.name"));
        assertEquals(List.of("x1", "y2"), bp.get("user.tags[]"));
        assertEquals(List.of("42"), bp.get("n"));
        List<String> in = c.userInputs();
        assertTrue(in.contains("alice-file.txt"));
        assertTrue(in.contains("name"), "JSON keys are inputs too");
        assertTrue(in.contains("1"), "query values still included");
    }

    @Test
    void formBodyParsed() {
        RequestContext c = ctx("application/x-www-form-urlencoded", "", "f=hello%20world&g=2", 65536);
        assertEquals(List.of("hello world"), c.bodyParams().get("f"));
        assertTrue(c.userInputs().contains("hello world"));
    }

    @Test
    void multipartOnlyNamesAndFileNames() {
        String body = "--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"report.pdf\"\r\n\r\nBINARY\r\n--b--";
        RequestContext c = ctx("multipart/form-data; boundary=b", "", body, 65536);
        assertEquals(List.of("report.pdf"), c.bodyParams().get("doc"));
        assertFalse(c.userInputs().contains("BINARY"));
    }

    @Test
    void bodyLimitAndSecondStreamIgnored() {
        RequestContext c = new RequestContext(new FakeRequest("text/plain", ""), null, false, 4);
        Object s1 = new Object();
        c.appendBody(s1, "abcdef".getBytes(StandardCharsets.UTF_8), 0, 6);
        c.appendBody(new Object(), "zz".getBytes(StandardCharsets.UTF_8), 0, 2);
        assertEquals(4, c.bodyLength());
        assertTrue(c.bodyTruncated());
    }

    @Test
    void truncatedJsonIsIgnoredNotGuessed() {
        RequestContext c = ctx("application/json", "", "{\"a\":\"unterminated", 65536);
        assertTrue(c.bodyParams().isEmpty());
    }

    @Test
    void inputsRecomputedWhenMoreBodyArrives() {
        RequestContext c = new RequestContext(new FakeRequest("application/x-www-form-urlencoded", ""), null, false, 1024);
        Object s = new Object();
        byte[] b = "k=first-value&j=second-value".getBytes(StandardCharsets.UTF_8);
        c.appendBody(s, b, 0, 13);
        assertTrue(c.userInputs().contains("first-value"));
        c.appendBody(s, b, 13, b.length - 13);
        assertTrue(c.userInputs().contains("second-value"));
    }

    @Test
    void asyncSnapshotFlow() {
        RequestContext c = ctx("application/json", "q=abc", "{\"k\":\"value-1\"}", 65536);
        ContextHolder.set(c);
        Runnable task = () -> { };
        AsyncContexts.submit(task);
        ContextHolder.clear();

        // worker thread side
        AsyncContexts.before(task);
        RequestContext w = ContextHolder.get();
        assertTrue(w.async);
        assertNull(w.request, "snapshot must not hold the recycled servlet request");
        assertEquals(c.requestId, w.requestId);
        assertEquals("http://h/api?q=abc", w.url());
        assertTrue(w.userInputs().contains("value-1"));
        AsyncContexts.after();
        assertNull(ContextHolder.get());

        // task is consumed once
        AsyncContexts.before(task);
        assertNull(ContextHolder.get());
    }

    @Test
    void asyncNeverClearsRealRequestContext() {
        RequestContext real = ctx("text/plain", "", "", 0);
        ContextHolder.set(real);
        AsyncContexts.before(new Object());
        AsyncContexts.after();
        assertSame(real, ContextHolder.get());
    }

    @Test
    void submitWithoutRequestIsNoop() {
        int before = AsyncContexts.pending();
        AsyncContexts.submit(new Object());
        assertEquals(before, AsyncContexts.pending());
    }
}
