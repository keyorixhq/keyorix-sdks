package com.keyorix;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** JSON string escapes must be decoded: a secret value has to come back byte-for-byte. */
class JsonParserEscapesTest {

    private static String value(String jsonStringBody) throws Exception {
        return JsonParser.parseSecretValue("{\"data\":{\"id\":1,\"value\":\"" + jsonStringBody + "\"}}");
    }

    @Test
    void decodesSingleCharacterEscapes() throws Exception {
        assertEquals("a\nb\tc\rd\be\ff", value("a\\nb\\tc\\rd\\be\\ff"));
        assertEquals("q\"q", value("q\\\"q"));
        assertEquals("back\\slash", value("back\\\\slash"));
        assertEquals("a/b", value("a\\/b"));
    }

    @Test
    void decodesTheExampleFromTheBugReport() throws Exception {
        String want = "line1\nline2 \"q\" back\\slash";
        assertEquals(want, value("line1\\nline2 \\\"q\\\" back\\\\slash"));
    }

    @Test
    void decodesUnicodeEscapes() throws Exception {
        assertEquals("café", value("caf\\u00e9"));
        assertEquals("\u0000", value("\\u0000"));
        assertEquals("é", value("\\u00E9"), "hex digits are case-insensitive");
    }

    @Test
    void decodesSurrogatePairs() throws Exception {
        // U+1F600 is the pair D83D DE00; a Java String holds it as two chars.
        String got = value("\\ud83d\\ude00");
        assertEquals("😀", got);
        assertEquals(1, got.codePointCount(0, got.length()));
    }

    @Test
    void literalNonAsciiPassesThrough() throws Exception {
        assertEquals("café 😀", value("café 😀"));
    }

    @Test
    void escapedBackslashBeforeClosingQuoteEndsTheString() throws Exception {
        // value is `end\` : the quote after \\ closes the string, it is not escaped.
        String json = "{\"data\":{\"value\":\"end\\\\\",\"other\":\"x\"}}";
        assertEquals("end\\", JsonParser.parseSecretValue(json));
        assertEquals("x", JsonParser.extractString(json, "other"));
    }

    @Test
    void escapedQuoteInsideDoesNotEndTheString() throws Exception {
        assertEquals("a\"b", value("a\\\"b"));
    }

    @Test
    void tokenWithEscapesIsDecodedToo() throws Exception {
        assertEquals("t\"k", JsonParser.parseToken("{\"data\":{\"token\":\"t\\\"k\"}}"));
    }

    @Test
    void malformedEscapeIsRejectedNotSilentlyCorrupted() throws Exception {
        assertThrows(KeyorixException.class, () -> value("bad\\q"));
        assertThrows(KeyorixException.class, () -> value("bad\\u12"));
        assertThrows(KeyorixException.class, () -> value("bad\\uZZZZ"));
    }

    @Test
    void unpairedSurrogateEscapesAreRejected() {
        assertThrows(KeyorixException.class, () -> value("\\ud800"));          // high alone
        assertThrows(KeyorixException.class, () -> value("\\udc00"));          // low alone
        assertThrows(KeyorixException.class, () -> value("\\ud83dx"));         // high followed by a plain char
        assertThrows(KeyorixException.class, () -> value("\\ud83d\\u0041")); // high followed by a non-low escape
        assertThrows(KeyorixException.class, () -> value("\\ude00\\ud83d")); // low followed by high
        assertThrows(KeyorixException.class, () -> value("\\ud83d\\ud83d")); // high followed by high
    }

    @Test
    void aValidSurrogatePairIsStillAccepted() throws Exception {
        assertEquals("a\ud83d\ude00b", value("a\\ud83d\\ude00b"));
    }
}
