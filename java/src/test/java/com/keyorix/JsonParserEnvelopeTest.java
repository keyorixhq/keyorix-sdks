package com.keyorix;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A 200 response that does not carry what the call needs (no data object, no
 * value, a value of the wrong type, or success=false) is an error, not an
 * empty or null result.
 */
class JsonParserEnvelopeTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "{}",
        "{\"success\":true}",
        "{\"success\":true,\"data\":null}",
        "{\"success\":true,\"data\":{}}",
        "{\"success\":true,\"data\":{\"value\":null}}",
        "{\"success\":true,\"data\":{\"value\":5}}",
        "{\"success\":true,\"data\":{\"value\":true}}",
        "{\"success\":true,\"data\":{\"value\":{\"a\":1}}}",
        "{\"success\":true,\"data\":{\"value\":[\"x\"]}}",
        "{\"success\":true,\"data\":\"x\"}",
        "{\"success\":true,\"data\":[]}",
        "{\"success\":true,\"data\":[{\"value\":\"x\"}]}",
        "{\"value\":\"top-level-only\"}",
        "{\"success\":false,\"data\":{\"value\":\"v\"}}",
        "{\"success\":false,\"error\":\"Boom\"}",
        "{\"success\":null,\"data\":{\"value\":\"v\"}}",
        "{\"success\":\"true\",\"data\":{\"value\":\"v\"}}",
        "{\"success\":1,\"data\":{\"value\":\"v\"}}",
        "{\"error\":\"SomethingWentWrong\"}",
        "[]", "null", "\"v\"", "42"
    })
    void secretValueResponseWithoutAValueIsAnError(String body) {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretValue(body));
    }

    @Test
    void wellFormedValueResponsesStillWork() throws Exception {
        assertEquals("v", JsonParser.parseSecretValue("{\"success\":true,\"data\":{\"value\":\"v\"}}"));
        assertEquals("v", JsonParser.parseSecretValue("{\"data\":{\"value\":\"v\"}}"));
        assertEquals("", JsonParser.parseSecretValue("{\"success\":true,\"data\":{\"value\":\"\"}}"));
    }

    @Test
    void loginResponseWithAWrongTypedTokenIsAnError() throws Exception {
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"success\":true,\"data\":{\"token\":{}}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"success\":true,\"data\":{\"token\":[\"t\"]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"success\":true,\"data\":{\"token\":12}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"success\":false,\"data\":{\"token\":\"t\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseToken("{\"success\":true,\"data\":null}"));
        // an absent or null token is reported by the caller (no-token / MFA handling)
        assertNull(JsonParser.parseToken("{\"success\":true,\"data\":{}}"));
        assertNull(JsonParser.parseToken("{\"success\":true,\"data\":{\"token\":null}}"));
        assertEquals("t", JsonParser.parseToken("{\"success\":true,\"data\":{\"token\":\"t\"}}"));
    }

    @Test
    void listAndSingleResponsesRequireSuccessAndData() {
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{\"success\":false,\"data\":{\"secrets\":[]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{\"data\":null}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":\"x\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":{}}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretList("{\"data\":{\"secrets\":[1]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseProjectList("{\"success\":false,\"data\":{\"projects\":[]}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseEnvironmentList("{\"data\":[]}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseDeletedSecretList("{\"success\":false}", 1));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedSecret("{\"success\":true}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseCreatedProject("{\"success\":false,\"data\":{\"id\":1,\"name\":\"n\"}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseSecretResponse("{\"data\":{}}"));
        assertThrows(KeyorixException.class, () -> JsonParser.parseTotalPages("{\"success\":false,\"data\":{\"total_pages\":1}}"));
    }

    @Test
    void emptyListsAreStillEmptyLists() throws Exception {
        assertTrue(JsonParser.parseSecretList("{\"success\":true,\"data\":{\"secrets\":[]}}").isEmpty());
        // a server that encodes an empty collection as null
        assertTrue(JsonParser.parseSecretList("{\"success\":true,\"data\":{\"secrets\":null}}").isEmpty());
        assertTrue(JsonParser.parseProjectList("{\"success\":true,\"data\":{\"projects\":[]}}").isEmpty());
    }

    @Test
    void mfaFlagsAreReadOnlyFromTheDataObject() throws Exception {
        String body = "{\"success\":true,\"data\":{\"mfa_required\":true,\"mfa_challenge\":\"c\"}}";
        assertTrue(JsonParser.extractBoolean(body, "mfa_required"));
        assertFalse(JsonParser.extractBoolean(body, "totp_available"));
        assertFalse(JsonParser.extractBoolean("{\"success\":true,\"data\":{\"mfa_required\":\"true\"}}", "mfa_required"));
        assertFalse(JsonParser.extractBoolean("{\"success\":true,\"data\":{\"x\":{\"mfa_required\":true}}}", "mfa_required"));
    }
}
