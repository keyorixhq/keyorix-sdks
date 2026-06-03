package com.keyorix;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeyorixClientTest {

    @Test
    void testClientConstruction() {
        KeyorixClient client = new KeyorixClient("http://localhost:8080", "test-token");
        assertNotNull(client);
    }

    @Test
    void testClientStripsTrailingSlash() {
        // Just verify construction doesn't throw
        KeyorixClient client = new KeyorixClient("http://localhost:8080/", "test-token");
        assertNotNull(client);
    }

    @Test
    void testSecretNotFoundException_isKeyorixException() {
        SecretNotFoundException ex = new SecretNotFoundException("not found");
        assertInstanceOf(KeyorixException.class, ex);
        assertEquals("not found", ex.getMessage());
    }

    @Test
    void testAuthException_isKeyorixException() {
        AuthException ex = new AuthException("unauthorized");
        assertInstanceOf(KeyorixException.class, ex);
        assertEquals("unauthorized", ex.getMessage());
    }

    @Test
    void testSecretModel() {
        Secret s = new Secret(1L, "db-password", "password", "production", 1L, "2026-01-01");
        assertEquals(1L, s.getId());
        assertEquals("db-password", s.getName());
        assertEquals("password", s.getType());
        assertEquals("production", s.getEnvironment());
        assertEquals(1L, s.getProjectId());
        assertTrue(s.toString().contains("db-password"));
    }

    @Test
    void testJsonParser_parseToken() {
        String json = "{\"data\":{\"token\":\"abc123\",\"user_id\":1}}";
        assertEquals("abc123", JsonParser.extractString(json, "token"));
    }

    @Test
    void testJsonParser_parseSecretValue() {
        String json = "{\"data\":{\"ID\":7,\"value\":\"supersecret\"}}";
        assertEquals("supersecret", JsonParser.parseSecretValue(json));
    }

    @Test
    void testJsonParser_parseSecretList() {
        String json = "{\"data\":{\"secrets\":[" +
            "{\"ID\":1,\"Name\":\"db-password\",\"Type\":\"password\",\"environment_name\":\"production\",\"ProjectID\":1,\"CreatedAt\":\"2026-01-01\"}," +
            "{\"ID\":2,\"Name\":\"api-key\",\"Type\":\"generic\",\"environment_name\":\"staging\",\"ProjectID\":2,\"CreatedAt\":\"2026-01-02\"}" +
            "]}}";
        java.util.List<Secret> secrets = JsonParser.parseSecretList(json);
        assertEquals(2, secrets.size());
        assertEquals("db-password", secrets.get(0).getName());
        assertEquals("production", secrets.get(0).getEnvironment());
        assertEquals(1L, secrets.get(0).getProjectId());
        assertEquals("api-key", secrets.get(1).getName());
        assertEquals("staging", secrets.get(1).getEnvironment());
        assertEquals(2L, secrets.get(1).getProjectId());
    }

    @Test
    void testJsonParser_emptySecretList() {
        String json = "{\"data\":{\"secrets\":[]}}";
        java.util.List<Secret> secrets = JsonParser.parseSecretList(json);
        assertTrue(secrets.isEmpty());
    }
}
