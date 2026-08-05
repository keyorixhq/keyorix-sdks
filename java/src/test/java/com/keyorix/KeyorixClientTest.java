package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeyorixClientTest {

    @Test
    void testClientConstruction() throws KeyorixException {
        KeyorixClient client = new KeyorixClient("http://localhost:8080", "test-token");
        assertNotNull(client);
    }

    @Test
    void testClientStripsTrailingSlash() throws KeyorixException {
        // Just verify construction doesn't throw
        KeyorixClient client = new KeyorixClient("http://localhost:8080/", "test-token");
        assertNotNull(client);
    }

    @Test
    void testClientAllowsHttps() throws KeyorixException {
        KeyorixClient client = new KeyorixClient("https://example.com:8443", "test-token");
        assertNotNull(client);
    }

    @Test
    void testClientAllowsLoopbackHttp() throws KeyorixException {
        assertNotNull(new KeyorixClient("http://localhost:8080", "test-token"));
        assertNotNull(new KeyorixClient("http://127.0.0.1:8080", "test-token"));
        assertNotNull(new KeyorixClient("http://[::1]:8080", "test-token"));
    }

    @Test
    void testClientRejectsNonLoopbackHttp() {
        assertThrows(KeyorixException.class, () -> new KeyorixClient("http://example.com:8080", "test-token"));
    }

    @Test
    void testClientRejectsNonHttpScheme() {
        assertThrows(KeyorixException.class, () -> new KeyorixClient("file:///etc/passwd", "test-token"));
        assertThrows(KeyorixException.class, () -> new KeyorixClient("ftp://example.com", "test-token"));
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
    void testKeyorixException_messageOmitsBody() {
        KeyorixException ex = new KeyorixException("Server returned 500", 500, "internal stack trace here");
        assertFalse(ex.getMessage().contains("internal stack trace here"));
        assertEquals(500, ex.getStatusCode());
        assertEquals("internal stack trace here", ex.getResponseBody());
    }

    @Test
    void testGet_redactsBodyFromMessage() throws IOException, KeyorixException {
        String raw = "internal: secret_key=super-sensitive-detail";
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/secrets", exchange -> {
            byte[] resp = raw.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(500, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();
        try {
            KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "test-token");
            KeyorixException ex = assertThrows(KeyorixException.class, () -> client.listSecrets(null));
            assertFalse(ex.getMessage().contains(raw), "message must not leak the raw response body");
            assertEquals(raw, ex.getResponseBody());
            assertEquals(500, ex.getStatusCode());
        } finally {
            server.stop(0);
        }
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
