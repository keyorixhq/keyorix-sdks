package com.keyorix;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 503 audit_unavailable: the server refused a write because its audit row could
 * not be recorded (real body shape: server/http/handlers/audit_unavailable.go).
 * Red before the change: AuditUnavailableException did not exist (compile error).
 */
class AuditUnavailableTest {

    private static final String VALUE = "audit-s3cr3t-must-not-leak";

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    private KeyorixClient clientAnswering503(String code) throws IOException, KeyorixException {
        String body = "{\"success\":false,\"code\":503,\"error\":\"" + code + "\",\"message\":\"echo " + VALUE + "\"}";
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/secrets", ex -> {
            ex.getRequestBody().readAllBytes();
            reply(ex, 503, body);
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
        if (status == 503) ex.getResponseHeaders().add("Retry-After", "5");
        ex.sendResponseHeaders(status, resp.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(resp);
        }
    }

    @Test
    void auditUnavailableIsTyped() throws Exception {
        KeyorixClient c = clientAnswering503("audit_unavailable");
        AuditUnavailableException e = assertThrows(AuditUnavailableException.class,
            () -> c.createSecret("proj-a", "prod", "n", VALUE));
        assertTrue(e instanceof KeyorixException);
        assertEquals(503, e.getStatusCode());
        assertEquals(KeyorixClient.CODE_AUDIT_UNAVAILABLE, e.getErrorCode());
        assertFalse(e.getMessage().contains(VALUE), e.getMessage());
        assertFalse(String.valueOf(e.getResponseBody()).contains(VALUE), e.getResponseBody());
    }

    @Test
    void other503StaysGeneric() throws Exception {
        KeyorixClient c = clientAnswering503("storage_unavailable");
        KeyorixException e = assertThrows(KeyorixException.class,
            () -> c.createSecret("proj-a", "prod", "n", VALUE));
        assertFalse(e instanceof AuditUnavailableException, "storage_unavailable must stay generic");
        assertEquals(503, e.getStatusCode());
    }
}
