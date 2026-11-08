package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class KeyorixClientTest {

    // Plain construction, trailing slash (only verifies construction doesn't
    // throw), https, and http on each loopback form (localhost, IPv4, IPv6).
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        "http://localhost:8080",
        "http://localhost:8080/",
        "https://example.com:8443",
        "http://127.0.0.1:8080",
        "http://[::1]:8080"
    })
    void testClientAcceptsValidServerUrl(String url) throws KeyorixException {
        assertNotNull(new KeyorixClient(url, "test-token"));
    }

    @Test
    void testClientRejectsNonLoopbackHttp() throws Exception {
        assertThrows(KeyorixException.class, () -> new KeyorixClient("http://example.com:8080", "test-token"));
    }

    @Test
    void testClientRejectsNonHttpScheme() throws Exception {
        assertThrows(KeyorixException.class, () -> new KeyorixClient("file:///etc/passwd", "test-token"));
        assertThrows(KeyorixException.class, () -> new KeyorixClient("ftp://example.com", "test-token"));
    }

    @Test
    void testSecretNotFoundException_isKeyorixException() throws Exception {
        SecretNotFoundException ex = new SecretNotFoundException("not found");
        assertInstanceOf(KeyorixException.class, ex);
        assertEquals("not found", ex.getMessage());
    }

    @Test
    void testAuthException_isKeyorixException() throws Exception {
        AuthException ex = new AuthException("unauthorized");
        assertInstanceOf(KeyorixException.class, ex);
        assertEquals("unauthorized", ex.getMessage());
    }

    @Test
    void testKeyorixException_messageOmitsBody() throws Exception {
        KeyorixException ex = new KeyorixException("Server returned 500", 500, "internal stack trace here");
        assertFalse(ex.getMessage().contains("internal stack trace here"));
        assertEquals(500, ex.getStatusCode());
        assertEquals("internal stack trace here", ex.getResponseBody());
    }

    @Test
    void testGetScoped_redactsBodyFromMessage() throws IOException, KeyorixException {
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
            KeyorixException ex = assertThrows(KeyorixException.class, () -> client.listSecretsScoped(1L, 1L));
            assertFalse(ex.getMessage().contains(raw), "message must not leak the raw response body");
            assertEquals(raw, ex.getResponseBody());
            assertEquals(500, ex.getStatusCode());
        } finally {
            server.stop(0);
        }
    }

    // ── Typed error mapping ─────────────────────────────────────────────────────
    // Every request path throws a typed exception that assertThrows can
    // distinguish for the three statuses callers most need to catch, not
    // just one generic KeyorixException.

    @Test
    void test401MapsToAuthException() throws IOException, KeyorixException {
        assertStatusMapsTo(401, AuthException.class);
    }

    @Test
    void test403MapsToForbiddenException() throws IOException, KeyorixException {
        assertStatusMapsTo(403, ForbiddenException.class);
    }

    @Test
    void test404MapsToNotFoundException() throws IOException, KeyorixException {
        assertStatusMapsTo(404, NotFoundException.class);
    }

    private void assertStatusMapsTo(int status, Class<? extends KeyorixException> expected) throws IOException, KeyorixException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/api/v1/projects", exchange -> {
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();
        try {
            KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "test-token");
            KeyorixException ex = assertThrows(expected, client::listProjects);
            assertEquals(status, ex.getStatusCode());
        } finally {
            server.stop(0);
        }
    }

    // ── TLS with a private CA ───────────────────────────────────────────────────
    // Proves the caCertPath constructor option actually gets verified
    // against, not just plumbed through and ignored. Uses a throwaway
    // self-signed cert (openssl) as its own private CA. Skipped gracefully
    // if openssl isn't on PATH.

    @Test
    void testTlsPrivateCa() throws Exception {
        try {
            new ProcessBuilder("openssl", "version").start().waitFor();
        } catch (IOException e) {
            return; // openssl not on PATH -- skip gracefully
        }

        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("keyorix-tls-test-");
        java.nio.file.Path keyPath = dir.resolve("key.pem");
        java.nio.file.Path certPath = dir.resolve("cert.pem");
        try {
            Process p = new ProcessBuilder(
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", keyPath.toString(), "-out", certPath.toString(),
                "-days", "1", "-subj", "/CN=localhost"
            ).redirectErrorStream(true).start();
            p.waitFor();
            assertEquals(0, p.exitValue(), "openssl cert generation failed");

            com.sun.net.httpserver.HttpsServer server =
                com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
            javax.net.ssl.SSLContext serverCtx = buildServerSslContext(keyPath, certPath);
            server.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(serverCtx));
            server.createContext("/health", exchange -> {
                byte[] resp = "{\"status\":\"healthy\"}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, resp.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(resp);
                }
            });
            server.start();
            try {
                int port = server.getAddress().getPort();
                KeyorixClient untrusted = new KeyorixClient("https://localhost:" + port, "tok");
                assertThrows(KeyorixException.class, untrusted::health,
                    "expected an untrusted self-signed cert to be rejected by default");

                KeyorixClient trusted = new KeyorixClient(
                    "https://localhost:" + port, "tok", java.time.Duration.ofSeconds(30), certPath.toString());
                assertTrue(trusted.health(), "health() should succeed once the private CA is supplied");
            } finally {
                server.stop(0);
            }
        } finally {
            java.nio.file.Files.deleteIfExists(keyPath);
            java.nio.file.Files.deleteIfExists(certPath);
            java.nio.file.Files.deleteIfExists(dir);
        }
    }

    private static javax.net.ssl.SSLContext buildServerSslContext(java.nio.file.Path keyPath, java.nio.file.Path certPath)
            throws Exception {
        // PKCS12 keystore built from the same openssl-generated key+cert, purely
        // to hand to the test's embedded HttpsServer -- unrelated to the
        // client-side trust logic under test in KeyorixClient itself.
        java.nio.file.Path p12 = java.nio.file.Files.createTempFile("keyorix-tls-test-", ".p12");
        try {
            Process p = new ProcessBuilder(
                "openssl", "pkcs12", "-export",
                "-inkey", keyPath.toString(), "-in", certPath.toString(),
                "-out", p12.toString(), "-passout", "pass:changeit", "-name", "server"
            ).redirectErrorStream(true).start();
            p.waitFor();
            assertEquals(0, p.exitValue(), "openssl pkcs12 export failed");

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(p12.toFile())) {
                ks.load(fis, "changeit".toCharArray());
            }
            javax.net.ssl.KeyManagerFactory kmf =
                javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, "changeit".toCharArray());
            javax.net.ssl.SSLContext ctx = javax.net.ssl.SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return ctx;
        } finally {
            java.nio.file.Files.deleteIfExists(p12);
        }
    }

    // ── Deprecated environment-only methods: removed since v0.3.0 ──────────────

    // Deliberately calls the removal-flagged methods: the test's purpose is to
    // pin that they still throw without contacting the server.
    @SuppressWarnings("removal")
    @Test
    void testListSecrets_deprecated_neverCallsServer() throws IOException, KeyorixException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        boolean[] called = { false };
        server.createContext("/", exchange -> {
            called[0] = true;
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
        });
        server.start();
        try {
            KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "test-token");
            KeyorixException ex = assertThrows(KeyorixException.class, () -> client.listSecrets("production"));
            assertTrue(ex.getMessage().contains("listSecretsScoped"));
            assertFalse(called[0], "listSecrets must not contact the server");
        } finally {
            server.stop(0);
        }
    }

    @SuppressWarnings("removal")
    @Test
    void testGetSecret_deprecated_neverCallsServer() throws IOException, KeyorixException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        boolean[] called = { false };
        server.createContext("/", exchange -> {
            called[0] = true;
            exchange.sendResponseHeaders(200, 0);
            exchange.close();
        });
        server.start();
        try {
            KeyorixClient client = new KeyorixClient("http://localhost:" + server.getAddress().getPort(), "test-token");
            KeyorixException ex = assertThrows(KeyorixException.class, () -> client.getSecret("db-password", "production"));
            assertTrue(ex.getMessage().contains("getSecretScoped"));
            assertFalse(called[0], "getSecret must not contact the server");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void testSecretModel() throws Exception {
        Secret s = new Secret(1L, "db-password", "password", "production", 1L, "2026-01-01");
        assertEquals(1L, s.getId());
        assertEquals("db-password", s.getName());
        assertEquals("password", s.getType());
        assertEquals("production", s.getEnvironment());
        assertEquals(1L, s.getProjectId());
        assertTrue(s.toString().contains("db-password"));
    }

    @Test
    void testJsonParser_parseToken() throws Exception {
        String json = "{\"data\":{\"token\":\"abc123\",\"user_id\":1}}";
        assertEquals("abc123", JsonParser.extractString(json, "token"));
    }

    @Test
    void testJsonParser_parseSecretValue() throws Exception {
        String json = "{\"data\":{\"ID\":7,\"value\":\"supersecret\"}}";
        assertEquals("supersecret", JsonParser.parseSecretValue(json));
    }

    @Test
    void testJsonParser_parseSecretList() throws Exception {
        String json = "{\"data\":{\"secrets\":[" +
            "{\"id\":1,\"name\":\"db-password\",\"type\":\"password\",\"environment_name\":\"production\",\"project_id\":1,\"created_at\":\"2026-01-01\"}," +
            "{\"id\":2,\"name\":\"api-key\",\"type\":\"generic\",\"environment_name\":\"staging\",\"project_id\":2,\"created_at\":\"2026-01-02\"}" +
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
    void testJsonParser_emptySecretList() throws Exception {
        String json = "{\"data\":{\"secrets\":[]}}";
        java.util.List<Secret> secrets = JsonParser.parseSecretList(json);
        assertTrue(secrets.isEmpty());
    }

    // ── Token handling ──────────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {
        "abc\r\nX-Injected: 1",
        "abc\n",
        "abc\r",
        "abc\u0000def",
        "abc\tdef",
        "abc\u007fdef",
        "t\u00f6ken"
    })
    void testClientRejectsTokenWithControlCharacters(String token) {
        KeyorixException ex = assertThrows(KeyorixException.class,
            () -> new KeyorixClient("http://localhost:8080", token));
        assertFalse(ex.getMessage().contains("abc"), "message must not contain the token");
        assertFalse(ex.getMessage().contains("X-Injected"), "message must not contain the token");
        assertFalse(ex.getMessage().contains("\u00f6"), "message must not contain the token");
    }

    @Test
    void testClientAcceptsOrdinaryTokens() throws KeyorixException {
        assertNotNull(new KeyorixClient("http://localhost:8080", "a.b-c_d~e+f/g="));
        assertNotNull(new KeyorixClient("http://localhost:8080", ""));
    }

    // Defence in depth: if an invalid value reaches the request layer anyway,
    // the JDK's message, which contains the raw header value, must not reach
    // the caller.
    @Test
    void testInvalidHeaderValueIsWrappedWithoutTheToken() throws Exception {
        java.net.HttpURLConnection conn =
            (java.net.HttpURLConnection) new java.net.URL("http://localhost:1/").openConnection();
        IOException ex = assertThrows(IOException.class,
            () -> KeyorixClient.setAuthorization(conn, "abc\r\nX-Injected: 1"));
        assertFalse(String.valueOf(ex.getMessage()).contains("abc"));
        assertFalse(String.valueOf(ex.getMessage()).contains("X-Injected"));
        assertNull(ex.getCause());
    }
}
