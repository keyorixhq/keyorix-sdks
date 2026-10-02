package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for getSecretByRef/getSecretIn and listSecretsScoped's pagination
 * follow. Red/green notes (see reports/SESSION-K.md for the full isolation
 * detail): getSecretByRef/getSecretIn did not exist before this fix —
 * NoSuchMethodError against the pre-fix class. listSecretsScoped's
 * pagination follow is a real behavioral regression fix: before this fix it
 * never sent page/page_size at all, so a scope with more secrets than the
 * server's default page size (20) was silently truncated with no error.
 */
class RefAndPaginationTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    private static void json(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws IOException {
        byte[] resp = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, resp.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(resp);
        }
    }

    private String queryParam(com.sun.net.httpserver.HttpExchange exchange, String key) {
        String query = exchange.getRequestURI().getQuery();
        if (query == null) return null;
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq == -1) continue;
            String k = part.substring(0, eq);
            if (k.equals(key)) return URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
        }
        return null;
    }

    // ── getSecretByRef / getSecretIn ────────────────────────────────────────

    @Test
    void getSecretByRef_roundTripsEscapedRefWithSpacesAndSlashesInName() throws IOException, KeyorixException {
        String ref = "my project/prod env/path/to/secret";
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/secrets/value", exchange -> {
            if (!exchange.getRequestURI().getPath().equals("/api/v1/secrets/value")) {
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
                return;
            }
            String gotRef = queryParam(exchange, "ref");
            json(exchange, 200, "{\"data\":{\"value\":\"value-for:" + gotRef + "\"}}");
        });
        server.start();

        KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "tok");
        assertEquals("value-for:" + ref, client.getSecretByRef(ref));
    }

    @Test
    void getSecretIn_buildsProjectEnvironmentName() throws IOException, KeyorixException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/secrets/value", exchange -> {
            String gotRef = queryParam(exchange, "ref");
            json(exchange, 200, "{\"data\":{\"value\":\"value-for:" + gotRef + "\"}}");
        });
        server.start();

        KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "tok");
        assertEquals("value-for:proj/env/name", client.getSecretIn("proj", "env", "name"));
    }

    // ── getSecretByRef error mapping: reuses the existing typed exceptions
    //    from #40, not a second error set. ─────────────────────────────────

    @ParameterizedTest
    @ValueSource(ints = {401, 403, 404})
    void getSecretByRef_mapsStatusToTypedException(int status) throws IOException, KeyorixException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/secrets/value", exchange -> {
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();

        KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "tok");
        KeyorixException ex = assertThrows(KeyorixException.class, () -> client.getSecretByRef("p/e/n"));
        if (status == 401) {
            assertInstanceOf(AuthException.class, ex);
        } else if (status == 403) {
            assertInstanceOf(ForbiddenException.class, ex);
        } else if (status == 404) {
            assertInstanceOf(NotFoundException.class, ex);
        } else {
            fail("unexpected status " + status);
        }
    }

    // ── listSecretsScoped pagination ────────────────────────────────────────

    @Test
    void listSecretsScoped_followsAllPages() throws IOException, KeyorixException {
        AtomicInteger pagesSeen = new AtomicInteger(0);
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/secrets", exchange -> {
            String page = queryParam(exchange, "page");
            pagesSeen.incrementAndGet();
            if ("2".equals(page)) {
                json(exchange, 200, "{\"data\":{\"secrets\":[{\"id\":2,\"name\":\"b\"}],\"total_pages\":2}}");
            } else {
                json(exchange, 200, "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"a\"}],\"total_pages\":2}}");
            }
        });
        server.start();

        KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "tok");
        List<Secret> secrets = client.listSecretsScoped(1L, 1L);
        assertEquals(2, secrets.size(), "must follow every page the server reports");
        assertEquals(2, pagesSeen.get(), "must request exactly 2 pages");
    }
}
