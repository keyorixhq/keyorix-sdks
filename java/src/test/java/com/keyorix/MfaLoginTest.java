package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MfaLoginTest {

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static HttpServer start(String loginBody, int verifyStatus, String verifyBody, AtomicReference<String> verifyRequest) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/auth/login", ex -> reply(ex, 200, loginBody));
        server.createContext("/auth/mfa/verify", ex -> {
            verifyRequest.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            reply(ex, verifyStatus, verifyBody);
        });
        server.start();
        return server;
    }

    private static String url(HttpServer s) {
        return "http://localhost:" + s.getAddress().getPort();
    }

    @Test
    void loginWithChallengeThrowsTypedException() throws Exception {
        HttpServer s = start("{\"data\":{\"mfa_required\":true,\"mfa_challenge\":\"chal-1\",\"totp_available\":true,\"webauthn_available\":true}}",
                200, "{}", new AtomicReference<>());
        try {
            MFARequiredException e = assertThrows(MFARequiredException.class, () -> Keyorix.login(url(s), "u", "p"));
            assertInstanceOf(AuthException.class, e);
            assertEquals("chal-1", e.getChallenge());
            assertEquals(List.of("totp", "webauthn"), e.getMethods());
            assertFalse(e.getMessage().contains("chal-1"));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void loginWithNeitherTokenNorChallengeIsGenericAuthException() throws Exception {
        HttpServer s = start("{\"data\":{}}", 200, "{}", new AtomicReference<>());
        try {
            AuthException e = assertThrows(AuthException.class, () -> Keyorix.login(url(s), "u", "p"));
            assertFalse(e instanceof MFARequiredException);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void mfaRequiredFalseIsNotAChallenge() throws Exception {
        HttpServer s = start("{\"data\":{\"mfa_required\":false,\"mfa_challenge\":\"x\"}}", 200, "{}", new AtomicReference<>());
        try {
            AuthException e = assertThrows(AuthException.class, () -> Keyorix.login(url(s), "u", "p"));
            assertFalse(e instanceof MFARequiredException);
        } finally {
            s.stop(0);
        }
    }

    @Test
    void verifyMfaReturnsSessionAndPostsChallengeAndCode() throws Exception {
        AtomicReference<String> req = new AtomicReference<>();
        HttpServer s = start("{}", 200, "{\"data\":{\"token\":\"sess\"}}", req);
        try {
            assertEquals("sess", Keyorix.verifyMfa(url(s), "chal-1", "123456"));
            assertTrue(req.get().contains("\"mfa_challenge\":\"chal-1\""));
            assertTrue(req.get().contains("\"code\":\"123456\""));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void verifyMfaWrongCodeIsAuthException() throws Exception {
        HttpServer s = start("{}", 401, "{\"error\":\"Unauthorized\"}", new AtomicReference<>());
        try {
            AuthException e = assertThrows(AuthException.class, () -> Keyorix.verifyMfa(url(s), "c", "000000"));
            assertEquals(401, e.getStatusCode());
        } finally {
            s.stop(0);
        }
    }

    @Test
    void verifyMfaRejectsNonLoopbackHttp() {
        assertThrows(KeyorixException.class, () -> Keyorix.verifyMfa("http://example.com", "c", "1"));
    }
}
