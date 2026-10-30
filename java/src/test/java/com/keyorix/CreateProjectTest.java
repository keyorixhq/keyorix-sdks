package com.keyorix;

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
 * Tests for KeyorixClient.createProject. Red before the change: the method did
 * not exist (compile error), matching Go's CreateProject, Node's createProject
 * and Python's create_project.
 */
class CreateProjectTest {

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastMethod = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    private KeyorixClient clientAnswering(int status, String respBody) throws IOException, KeyorixException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/projects", ex -> {
            lastMethod.set(ex.getRequestMethod());
            lastAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            lastBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] resp = respBody.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, resp.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();
        return new KeyorixClient("http://127.0.0.1:" + server.getAddress().getPort(), "test-token");
    }

    @Test
    void postsNameAndDescriptionAndParsesProject() throws Exception {
        KeyorixClient c = clientAnswering(201,
            "{\"data\":{\"id\":12,\"name\":\"billing\",\"description\":\"made by \\\"test\\\"\",\"created_at\":\"2026-10-30T00:00:00Z\"}}");
        Project p = c.createProject("billing", "made by \"test\"");
        assertEquals("POST", lastMethod.get());
        assertEquals("Bearer test-token", lastAuth.get());
        assertEquals("{\"name\":\"billing\",\"description\":\"made by \\\"test\\\"\"}", lastBody.get());
        assertEquals(12, p.getId());
        assertEquals("billing", p.getName());
        assertEquals("2026-10-30T00:00:00Z", p.getCreatedAt());
    }

    @Test
    void nullDescriptionIsSentEmpty() throws Exception {
        KeyorixClient c = clientAnswering(201, "{\"data\":{\"id\":1,\"name\":\"p\"}}");
        c.createProject("p", null);
        assertEquals("{\"name\":\"p\",\"description\":\"\"}", lastBody.get());
    }

    @Test
    void errorsAreTyped() throws Exception {
        assertThrows(AuthException.class, () -> clientAnswering(401, "{\"error\":\"Unauthorized\"}").createProject("p", ""));
        stopServer();
        assertThrows(ForbiddenException.class, () -> clientAnswering(403, "{\"error\":\"Forbidden\"}").createProject("p", ""));
    }
}
