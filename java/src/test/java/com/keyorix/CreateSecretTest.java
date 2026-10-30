package com.keyorix;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for KeyorixClient.createSecret. Red before the change: the method and
 * SecretAlreadyExistsException did not exist (compile error).
 */
class CreateSecretTest {

    private static final String VALUE = "pa\"ss\nword-s3cr3t-must-not-leak";
    private static final String LEAK_MARKER = "s3cr3t-must-not-leak";

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    private KeyorixClient clientAnswering(int status, String respBody) throws IOException, KeyorixException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/secrets", ex -> {
            lastBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            lastAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            assertEquals("POST", ex.getRequestMethod());
            reply(ex, status, respBody);
        });
        server.createContext("/api/v1/projects", ex -> {
            String path = ex.getRequestURI().getPath();
            if (path.equals("/api/v1/projects")) {
                reply(ex, 200, "{\"data\":{\"projects\":[{\"id\":10,\"name\":\"proj-a\"}]}}");
            } else {
                reply(ex, 200, "{\"data\":{\"environments\":[{\"id\":101,\"name\":\"prod\",\"project_id\":10}]}}");
            }
        });
        server.start();
        return new KeyorixClient("http://127.0.0.1:" + server.getAddress().getPort(), "test-token");
    }

    private static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] resp = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, resp.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(resp);
        }
    }

    @Test
    void createsByNameAndSendsScopedBody() throws Exception {
        KeyorixClient c = clientAnswering(201,
            "{\"data\":{\"id\":7,\"project_id\":10,\"environment_id\":101,\"name\":\"db-password\",\"type\":\"generic\"}}");
        Secret s = c.createSecret("proj-a", "prod", "db-password", VALUE);
        assertEquals(7, s.getId());
        assertEquals("db-password", s.getName());
        assertEquals(10, s.getProjectId());
        assertEquals("generic", s.getType());
        assertEquals("Bearer test-token", lastAuth.get());
        String sent = lastBody.get();
        assertTrue(sent.contains("\"project_id\":10") && sent.contains("\"environment_id\":101"), sent);
        assertTrue(sent.contains("\"type\":\"generic\""), sent);
        // value is JSON-escaped (quote, newline), not truncated at the first special character
        assertTrue(sent.contains("\"value\":\"pa\\\"ss\\nword-s3cr3t-must-not-leak\""), sent);
    }

    @Test
    void createsByIdWithTypeAndDescription() throws Exception {
        KeyorixClient c = clientAnswering(201, "{\"data\":{\"id\":1,\"name\":\"n\",\"type\":\"password\",\"project_id\":3}}");
        Secret s = c.createSecret(3L, 4L, "n", "v", "password", "a note");
        assertEquals("password", s.getType());
        String sent = lastBody.get();
        assertTrue(sent.contains("\"project_id\":3,\"environment_id\":4"), sent);
        assertTrue(sent.contains("\"type\":\"password\"") && sent.contains("\"description\":\"a note\""), sent);
    }

    @Test
    void duplicateNameIsTyped() throws Exception {
        KeyorixClient c = clientAnswering(409,
            "{\"success\":false,\"error\":\"ConflictError\",\"message\":\"Secret with this name already exists\",\"code\":409}");
        SecretAlreadyExistsException e = assertThrows(SecretAlreadyExistsException.class,
            () -> c.createSecret(10L, 101L, "dup", VALUE, null, null));
        assertEquals(409, e.getStatusCode());
        assertEquals("ConflictError", e.getErrorCode());
    }

    @Test
    void unauthenticatedIsAuthException() throws Exception {
        KeyorixClient c = clientAnswering(401, "{\"error\":\"Unauthorized\"}");
        assertThrows(AuthException.class, () -> c.createSecret(10L, 101L, "n", VALUE, null, null));
    }

    @Test
    void valueNeverAppearsInExceptions() throws Exception {
        String escaped = JsonParser.quote(VALUE);
        escaped = escaped.substring(1, escaped.length() - 1);
        // a server that echoes the request: once JSON-escaped (as a JSON body would) and once raw
        String echo = "{\"error\":\"ValidationError\",\"message\":\"esc=" + escaped + "\"} raw=" + VALUE;
        for (int status : new int[] {400, 401, 403, 409, 500}) {
            KeyorixClient c = clientAnswering(status, echo);
            KeyorixException e = assertThrows(KeyorixException.class,
                () -> c.createSecret(10L, 101L, "n", VALUE, null, null), "status " + status);
            assertFalse(String.valueOf(e.getMessage()).contains(LEAK_MARKER), "message, status " + status);
            assertFalse(String.valueOf(e.getResponseBody()).contains(LEAK_MARKER), "body, status " + status);
            assertFalse(e.toString().contains(LEAK_MARKER), "toString, status " + status);
            stopServer();
        }
    }

    @Test
    void secretToStringCarriesNoValue() throws Exception {
        KeyorixClient c = clientAnswering(201, "{\"data\":{\"id\":1,\"name\":\"n\",\"type\":\"generic\",\"project_id\":3}}");
        assertFalse(c.createSecret(3L, 4L, "n", VALUE, null, null).toString().contains(LEAK_MARKER));
    }

    @Test
    void jsonQuoteEscapesControlCharacters() {
        assertEquals("\"a\\\"b\\\\c\\n\\t\\u0001\"", JsonParser.quote("a\"b\\c\n\t\u0001"));
    }
}
