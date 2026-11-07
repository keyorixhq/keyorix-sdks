package com.keyorix;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * How JsonParser reads a response: the whole body must be well-formed JSON, a
 * key is looked up only where the API puts it, and the last of several equal
 * keys wins.
 */
class JsonParserStructureTest {

    // ── malformed or truncated bodies are an SDK error, never a partial result ──

    @Test
    void truncatedSecretListIsAnError() {
        String full = "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"a\",\"project_id\":1},"
            + "{\"id\":2,\"name\":\"b\",\"project_id\":1}],\"total_pages\":1}}";
        assertEquals(2, assertDoesNotThrowList(full));
        // every proper prefix of a valid body is rejected, including the ones that happen to end after a full item
        for (int n = 0; n < full.length(); n++) {
            String cut = full.substring(0, n);
            assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(cut), "prefix length " + n);
        }
    }

    private static int assertDoesNotThrowList(String json) {
        try {
            return JsonParser.parseSecretList(json).size();
        } catch (KeyorixException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void truncatedSingleValuesAreAnError() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"abc"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"abc\""));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"abc\"}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"data\":{\"token\":\"t\""));
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"data\":{\"total_pages\":3"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseProjectList("{\"data\":{\"projects\":[{\"id\":1,\"name\":\"p\"}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseEnvironmentList("{\"data\":{\"environments\":[{\"id\":1"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseDeletedSecretList("{\"data\":{\"deleted\":[{\"id\":1,\"name\":\"x\"", 1));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedSecret("{\"data\":{\"id\":1,\"name\":\"x\""));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedProject("{\"data\":{\"id\":1,\"name\":\"x\""));
    }

    @Test
    void emptyOrNonJsonBodyIsAnError() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList(""));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("<html>502</html>"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseProjectList(null));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("[]"));
    }

    @Test
    void trailingDataIsAnError() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"v\"}} {}"));
    }

    @Test
    void malformedEscapeIsAnSdkError() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"bad\\q\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue("{\"data\":{\"value\":\"bad\\u12\"}}"));
    }

    @Test
    void errorBodyThatIsNotJsonYieldsNoErrorCode() {
        assertNull(JsonParser.errorCode("<html>"));
        assertNull(JsonParser.errorCode(""));
        assertNull(JsonParser.errorCode(null));
        assertEquals("SecretSuspended", JsonParser.errorCode("{\"error\":\"SecretSuspended\"}"));
        assertNull(JsonParser.errorCode("{\"error\":{\"x\":1}}"));
    }

    // ── a key is only read at its own level ──

    @Test
    void keyInsideANestedObjectIsNotReturned() throws Exception {
        assertNull(JsonParser.parseToken("{\"data\":{\"user\":{\"token\":\"decoy\"}}}"));
        assertEquals("real", JsonParser.parseToken("{\"data\":{\"user\":{\"token\":\"decoy\"},\"token\":\"real\"}}"));
    }

    @Test
    void keyInsideAStringValueIsNotReturned() throws Exception {
        String json = "{\"data\":{\"note\":\"x \\\"value\\\":\\\"decoy\\\"\",\"value\":\"real\"}}";
        assertEquals("real", JsonParser.parseSecretValue(json));
    }

    @Test
    void keyInsideAnotherFieldOfAListItemIsNotReturned() throws Exception {
        String json = "{\"data\":{\"secrets\":[{\"meta\":{\"id\":99,\"name\":\"decoy\"},\"id\":1,\"name\":\"real\",\"project_id\":5}]}}";
        List<Secret> l = JsonParser.parseSecretList(json);
        assertEquals(1, l.size());
        assertEquals("real", l.get(0).getName());
        assertEquals(1L, l.get(0).getId());
    }

    @Test
    void arrayKeyNestedElsewhereIsNotUsed() throws Exception {
        String json = "{\"data\":{\"other\":{\"secrets\":[{\"id\":9,\"name\":\"decoy\"}]},\"secrets\":[]}}";
        assertTrue(JsonParser.parseSecretList(json).isEmpty());
    }

    // ── duplicate keys: last wins, as in the Go, Node and Python SDKs ──

    @Test
    void lastDuplicateKeyWins() throws Exception {
        assertEquals("second", JsonParser.parseSecretValue("{\"data\":{\"value\":\"first\",\"value\":\"second\"}}"));
        assertEquals("t2", JsonParser.parseToken("{\"data\":{\"token\":\"t1\",\"x\":1,\"token\":\"t2\"}}"));
        assertEquals(7, JsonParser.parseTotalPages("{\"data\":{\"total_pages\":2,\"total_pages\":7}}"));
        List<Secret> l = JsonParser.parseSecretList(
            "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"a\",\"name\":\"b\",\"project_id\":1}]}}");
        assertEquals("b", l.get(0).getName());
    }

    @Test
    void lastDuplicateDataKeyWins() throws Exception {
        assertEquals("v2", JsonParser.parseSecretValue("{\"data\":{\"value\":\"v1\"},\"data\":{\"value\":\"v2\"}}"));
    }
}
