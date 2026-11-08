package com.zhuwei.rasp.core;

import com.zhuwei.rasp.core.util.Json;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonTest {

    @Test
    void roundTrip() {
        String s = "{\"a\":1,\"b\":[true,false,null,\"x\\\"y\\n\"],\"c\":{\"d\":1.5,\"e\":\"\\u4e2d\"}}";
        Map<String, Object> m = Json.parseObject(s);
        assertEquals(1L, m.get("a"));
        List<?> b = (List<?>) m.get("b");
        assertEquals("x\"y\n", b.get(3));
        assertEquals("中", Json.obj(m, "c").get("e"));
        assertEquals(m, Json.parseObject(Json.stringify(m)));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":}"));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[1,2] x"));
    }

    @Test
    void escapesControlChars() {
        assertTrue(Json.stringify("\u0001").contains("\\u0001"));
    }
}
