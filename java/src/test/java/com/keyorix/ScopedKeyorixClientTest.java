package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Scoped list/get secret tests. Mirrors the same two-project test matrix as
 * the Go/Python/Node SDKs: two projects, each with its own "prod"
 * environment (environment names are unique per project, not globally) and
 * its own "db-password" secret, plus a duplicated name to exercise the
 * ambiguous-match case.
 */
class ScopedKeyorixClientTest {

    private HttpServer server;
    private AtomicInteger projectListCalls;

    @BeforeEach
    void startServer() throws IOException {
        projectListCalls = new AtomicInteger(0);
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);

        server.createContext("/api/v1/projects", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/api/v1/projects")) {
                notFound(exchange);
                return;
            }
            projectListCalls.incrementAndGet();
            json(exchange, "{\"data\":{\"projects\":[{\"ID\":10,\"Name\":\"proj-a\"},{\"ID\":20,\"Name\":\"proj-b\"}]}}");
        });
        server.createContext("/api/v1/projects/10/environments", exchange ->
            json(exchange, "{\"data\":{\"environments\":[{\"ID\":101,\"Name\":\"prod\",\"ProjectID\":10}]}}"));
        server.createContext("/api/v1/projects/20/environments", exchange ->
            json(exchange, "{\"data\":{\"environments\":[{\"ID\":201,\"Name\":\"prod\",\"ProjectID\":20}]}}"));
        server.createContext("/api/v1/secrets", exchange -> {
            String query = exchange.getRequestURI().getQuery();
            if (query != null && query.contains("project_id=10") && query.contains("environment_id=101")) {
                json(exchange, "{\"data\":{\"secrets\":[{\"ID\":1,\"Name\":\"db-password\"}]}}");
            } else if (query != null && query.contains("project_id=20") && query.contains("environment_id=201")) {
                json(exchange, "{\"data\":{\"secrets\":["
                    + "{\"ID\":2,\"Name\":\"db-password\"},"
                    + "{\"ID\":3,\"Name\":\"ambiguous-secret\"},"
                    + "{\"ID\":4,\"Name\":\"ambiguous-secret\"}"
                    + "]}}");
            } else {
                notFound(exchange);
            }
        });
        server.createContext("/api/v1/secrets/1", exchange -> json(exchange, "{\"data\":{\"value\":\"secret-a\"}}"));
        server.createContext("/api/v1/secrets/2", exchange -> json(exchange, "{\"data\":{\"value\":\"secret-b\"}}"));
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private static void json(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] resp = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, resp.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(resp);
        }
    }

    private static void notFound(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        exchange.sendResponseHeaders(404, -1);
        exchange.close();
    }

    private KeyorixClient client() throws KeyorixException {
        return new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "test-token");
    }

    // ── Table matrix: listSecretsScoped ─────────────────────────────────────

    static List<Object[]> listSecretsScopedCases() {
        return Arrays.asList(
            new Object[] { "by name, proj-a/prod", "proj-a", "prod", new long[] { 1 } },
            new Object[] { "by name, proj-b/prod", "proj-b", "prod", new long[] { 2, 3, 4 } }
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("listSecretsScopedCases")
    void listSecretsScoped_byName_tableMatrix(String label, String project, String environment, long[] wantIds)
            throws KeyorixException {
        List<Secret> secrets = client().listSecretsScoped(project, environment);
        assertEquals(wantIds.length, secrets.size(), label);
        for (int i = 0; i < wantIds.length; i++) {
            assertEquals(wantIds[i], secrets.get(i).getId(), label + " secret[" + i + "]");
        }
    }

    @Test
    void listSecretsScoped_byId_projA() throws KeyorixException {
        List<Secret> secrets = client().listSecretsScoped(10L, 101L);
        assertEquals(1, secrets.size());
        assertEquals(1L, secrets.get(0).getId());
    }

    @Test
    void listSecretsScoped_byId_projB() throws KeyorixException {
        List<Secret> secrets = client().listSecretsScoped(20L, 201L);
        assertEquals(3, secrets.size());
    }

    @Test
    void listSecretsScoped_byId_neverListsProjectsOrEnvironments() throws KeyorixException {
        client().listSecretsScoped(10L, 101L);
        assertEquals(0, projectListCalls.get(), "must not call GET /api/v1/projects when given numeric IDs");
    }

    @Test
    void listSecretsScoped_unknownProject_throws() {
        assertThrows(KeyorixException.class, () -> client().listSecretsScoped("ghost", "prod"));
    }

    @Test
    void listSecretsScoped_unknownEnvironment_throws() {
        assertThrows(KeyorixException.class, () -> client().listSecretsScoped("proj-a", "ghost"));
    }

    @Test
    void resolveProject_cachesAcrossCalls() throws KeyorixException {
        KeyorixClient c = client();
        c.listSecretsScoped("proj-a", "prod");
        c.listSecretsScoped("proj-a", "prod");
        assertEquals(1, projectListCalls.get(), "GET /api/v1/projects must be called once, then cached");
    }

    // ── getSecretScoped ──────────────────────────────────────────────────────

    @Test
    void getSecretScoped_projA_resolvesItsOwnDbPassword() throws KeyorixException {
        assertEquals("secret-a", client().getSecretScoped("db-password", "proj-a", "prod"));
    }

    @Test
    void getSecretScoped_projB_resolvesItsOwnDbPassword_notProjAs() throws KeyorixException {
        assertEquals("secret-b", client().getSecretScoped("db-password", "proj-b", "prod"));
    }

    @Test
    void getSecretScoped_missingName_throwsSecretNotFoundException() {
        assertThrows(SecretNotFoundException.class,
            () -> client().getSecretScoped("does-not-exist", "proj-a", "prod"));
    }

    @Test
    void getSecretScoped_ambiguousName_throwsAmbiguousSecretExceptionWithBothIds() throws KeyorixException {
        KeyorixClient c = client();
        AmbiguousSecretException ex = assertThrows(AmbiguousSecretException.class,
            () -> c.getSecretScoped("ambiguous-secret", "proj-b", "prod"));
        assertEquals(Arrays.asList(3L, 4L), ex.getIds());
    }
}
