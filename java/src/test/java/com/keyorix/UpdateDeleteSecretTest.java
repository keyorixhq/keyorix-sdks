package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for updateSecret / deleteSecret (and their ById primitives)
 * against a local stub server: request shape, typed errors, and the rule that
 * the secret value never appears in an exception. The behaviour against a real
 * server is in {@link ContractTest}.
 */
class UpdateDeleteSecretTest {

    private static final String NEW_VALUE = "rotated-value-xyz";

    /** One request the stub saw: "METHOD /path", the Authorization header, and the body. */
    private static final class Call {
        final String line;
        final String auth;
        final String body;

        Call(String line, String auth, String body) {
            this.line = line;
            this.auth = auth;
            this.body = body;
        }
    }

    /** Answers each request via {@code respond(exchange, body)} and records it. */
    private HttpServer server;
    private final List<Call> calls = new CopyOnWriteArrayList<>();

    private KeyorixClient start(BiConsumer<com.sun.net.httpserver.HttpExchange, String> respond) throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            calls.add(new Call(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath(),
                exchange.getRequestHeaders().getFirst("Authorization"), body));
            respond.accept(exchange, body);
            exchange.close();
        });
        server.start();
        return new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "tok");
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) {
        try {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, status == 204 ? -1 : b.length);
            if (status != 204) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(b);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void updateSecretByIdSendsPutWithValueAndReturnsMetadata() throws Exception {
        KeyorixClient c = start((ex, b) -> reply(ex, 200,
            "{\"data\":{\"id\":7,\"name\":\"db\",\"type\":\"generic\",\"project_id\":3}}"));
        Secret s = c.updateSecretById(7, NEW_VALUE);
        assertEquals("PUT /api/v1/secrets/7", calls.get(0).line);
        assertEquals("Bearer tok", calls.get(0).auth);
        assertEquals("{\"value\":\"" + NEW_VALUE + "\"}", calls.get(0).body);
        assertEquals(7, s.getId());
        assertEquals("db", s.getName());
        assertEquals(3, s.getProjectId());
        assertFalse(s.toString().contains(NEW_VALUE));
    }

    @Test
    void updateValueIsEncodedAsValidJson() throws Exception {
        KeyorixClient c = start((ex, b) -> reply(ex, 200, "{\"data\":{\"id\":7,\"name\":\"db\"}}"));
        c.updateSecretById(7, "line1\nline2 \"q\" \\ \t\u0001");
        assertEquals("{\"value\":\"line1\\nline2 \\\"q\\\" \\\\ \\t\\u0001\"}", calls.get(0).body);
    }

    @Test
    void updateRefusesAnEmptyValueWithoutARequest() throws Exception {
        KeyorixClient c = start((ex, b) -> reply(ex, 200, "{}"));
        assertThrows(KeyorixException.class, () -> c.updateSecretById(7, ""));
        assertThrows(KeyorixException.class, () -> c.updateSecretById(7, null));
        assertTrue(calls.isEmpty(), "an empty value must not reach the server");
    }

    @Test
    void exceptionsNeverCarryTheValueEvenIfTheServerEchoesIt() throws Exception {
        String tricky = "pa\"ss" + NEW_VALUE; // the quote forces a JSON escape
        for (int status : new int[] {400, 403, 404, 409, 500}) {
            calls.clear();
            KeyorixClient c = start((ex, b) -> reply(ex, status,
                "{\"error\":\"X\",\"message\":\"bad value " + tricky + " / escaped pa\\\"ss" + NEW_VALUE + "\"}"));
            KeyorixException e = assertThrows(KeyorixException.class, () -> c.updateSecretById(7, tricky),
                "status " + status);
            assertFalse(e.getMessage().contains(NEW_VALUE), "message, status " + status);
            assertFalse(String.valueOf(e.getResponseBody()).contains(NEW_VALUE), "response body, status " + status);
            assertEquals(status, e.getStatusCode());
            server.stop(0);
        }
    }

    @Test
    void typedExceptionsForUpdateAndDelete() throws Exception {
        Class<?>[] types = {AuthException.class, ForbiddenException.class, NotFoundException.class};
        int[] statuses = {401, 403, 404};
        for (int i = 0; i < statuses.length; i++) {
            int status = statuses[i];
            KeyorixClient c = start((ex, b) -> reply(ex, status, "{}"));
            assertInstanceOf(types[i], assertThrows(KeyorixException.class, () -> c.updateSecretById(1, "v")),
                "update " + status);
            assertInstanceOf(types[i], assertThrows(KeyorixException.class, () -> c.deleteSecretById(1)),
                "delete " + status);
            server.stop(0);
        }
    }

    @Test
    void deleteReturnsThePurgeDateWhenSent() throws Exception {
        KeyorixClient c = start((ex, b) -> {
            ex.getResponseHeaders().add("Keyorix-Purge-At", "2026-11-30T14:56:16Z");
            reply(ex, 204, "");
        });
        assertEquals("2026-11-30T14:56:16Z", c.deleteSecretById(9));
        assertEquals("DELETE /api/v1/secrets/9", calls.get(0).line);
        assertEquals("", calls.get(0).body);
    }

    @Test
    void deleteWithoutAPurgeDateStillSucceeds() throws Exception {
        KeyorixClient c = start((ex, b) -> reply(ex, 204, ""));
        assertEquals("", c.deleteSecretById(9));
    }

    @Test
    void namesResolveToIdsAndAmbiguityNeverWrites() throws Exception {
        String listing = "{\"data\":{\"secrets\":[{\"id\":1,\"name\":\"dup\"},{\"id\":2,\"name\":\"dup\"},"
            + "{\"id\":3,\"name\":\"solo\"}],\"total_pages\":1}}";
        KeyorixClient c = start((ex, b) -> {
            switch (ex.getRequestMethod()) {
                case "GET": reply(ex, 200, listing); break;
                case "PUT": reply(ex, 200, "{\"data\":{\"id\":3,\"name\":\"solo\"}}"); break;
                default: reply(ex, 204, "");
            }
        });
        assertEquals(3, c.updateSecret(1, 1, "solo", "v").getId());
        c.deleteSecret(1, 1, "solo");
        assertThrows(AmbiguousSecretException.class, () -> c.updateSecret(1, 1, "dup", "v"));
        assertThrows(AmbiguousSecretException.class, () -> c.deleteSecret(1, 1, "dup"));
        assertThrows(SecretNotFoundException.class, () -> c.updateSecret(1, 1, "ghost", "v"));

        List<String> writes = new ArrayList<>();
        for (Call call : calls) {
            if (call.line.startsWith("PUT") || call.line.startsWith("DELETE")) writes.add(call.line);
        }
        assertEquals(List.of("PUT /api/v1/secrets/3", "DELETE /api/v1/secrets/3"), writes);
    }
}
