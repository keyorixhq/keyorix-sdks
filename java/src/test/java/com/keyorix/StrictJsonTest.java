package com.keyorix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** The reader accepts exactly one well-formed JSON value and rejects everything else. */
class StrictJsonTest {

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(String json) throws KeyorixException {
        return (Map<String, Object>) StrictJson.parse(json);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{}", "[]", "[[]]", "[1,2,3]", "{\"a\":null}", "\"x\"", "0", "-0", "1E2", "1.5e-3", "true", "false", "null",
        " \t\r\n{ \"a\" : [ 1 , 2 ] } \n", "[\"\\u0000\"]", "[\"\\uD800\"]", "[\"\\ud83d\\ude00\"]", "\"\u00e9\"",
        "{\"a\":1,\"a\":2}", "[123e65]", "[-1]", "[0.0]"
    })
    void acceptsWellFormedValues(String json) {
        assertDoesNotThrow(() -> StrictJson.parse(json));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "", " ", "{", "[", "{\"a\"", "{\"a\":", "{\"a\":1", "{\"a\":1,", "[1,", "[1", "\"abc", "\"abc\\", "\"\\u12",
        "{\"a\":1}x", "{} {}", "[1]]", "{\"a\":1}}", "nul", "tru", "truefalse",
        "{'a':1}", "{a:1}", "{\"a\" 1}", "{\"a\":1 \"b\":2}", "{,}", "[,]", "[1,]", "{\"a\":1,}", "[1 2]",
        "01", "-", "+1", "1.", ".5", "1e", "1e+", "0x10", "-01", "NaN", "Infinity", "-Infinity", "[1.e1]",
        "\"\\q\"", "\"\\x41\"", "\"\\u00G0\"", "\"\\u\uff10\uff10\uff10\uff10\"", "\"\\U0041\"", "\"a\nb\"", "\"a\tb\"", "\"a\u0000b\"",
        "\ufeff{}", "\u00a0{}", "[\"a\"\u0000]", "{\"a\":\"b\"\u0000}", "/* c */{}", "{}//", "[-]"
    })
    void rejectsMalformedValues(String json) {
        assertThrows(KeyorixException.class, () -> StrictJson.parse(json));
    }

    @Test
    void nullInputIsRejected() {
        assertThrows(KeyorixException.class, () -> StrictJson.parse(null));
    }

    @Test
    void lastDuplicateKeyWins() throws Exception {
        Map<String, Object> m = obj("{\"value\":\"first\",\"other\":1,\"value\":\"second\"}");
        assertEquals("second", m.get("value"));
        assertEquals(2, m.size());
    }

    @Test
    void decodesEscapes() throws Exception {
        assertEquals("a\nb\t\"\\/\b\f\r", StrictJson.parse("\"a\\nb\\t\\\"\\\\\\/\\b\\f\\r\""));
        assertEquals("\ud83d\ude00", StrictJson.parse("\"\\ud83d\\ude00\""));
        assertEquals("end\\", StrictJson.parse("\"end\\\\\""));
    }

    @Test
    void numbersKeepTheirText() throws Exception {
        assertEquals("9223372036854775807", ((StrictJson.Num) StrictJson.parse("9223372036854775807")).text);
        assertEquals(Long.MAX_VALUE, ((StrictJson.Num) StrictJson.parse("9223372036854775807")).asLong());
        assertThrows(NumberFormatException.class, () -> ((StrictJson.Num) StrictJson.parse("9223372036854775808")).asLong());
        assertThrows(NumberFormatException.class, () -> ((StrictJson.Num) StrictJson.parse("1.5")).asLong());
        assertThrows(NumberFormatException.class, () -> ((StrictJson.Num) StrictJson.parse("1e2")).asLong());
    }

    @Test
    void arraysAndNullsAreTyped() throws Exception {
        List<?> l = (List<?>) StrictJson.parse("[null,true,\"s\"]");
        assertSame(StrictJson.NULL, l.get(0));
        assertEquals(Boolean.TRUE, l.get(1));
        assertEquals("s", l.get(2));
    }

    @Test
    void deepNestingIsRejectedNotAStackOverflow() {
        String deep = "[".repeat(100000) + "]".repeat(100000);
        assertThrows(KeyorixException.class, () -> StrictJson.parse(deep));
        String ok = "[".repeat(100) + "]".repeat(100);
        assertDoesNotThrow(() -> StrictJson.parse(ok));
    }

    @Test
    void errorMessageDoesNotContainTheInput() {
        KeyorixException e = assertThrows(KeyorixException.class,
            () -> StrictJson.parse("{\"value\":\"s3cret-do-not-leak\""));
        assertFalse(e.getMessage().contains("s3cret"));
    }
}
