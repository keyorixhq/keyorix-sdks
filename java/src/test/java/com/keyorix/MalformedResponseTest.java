package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** End to end: a response the client cannot trust surfaces as KeyorixException, never as a partial or empty result. */
class MalformedResponseTest {

    private static HttpServer serve(int status, String body) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
            if (b.length > 0) {
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(b);
                }
            }
            ex.close();
        });
        server.start();
        return server;
    }

    private static String url(HttpServer s) {
        return "http://localhost:" + s.getAddress().getPort();
    }

    private static KeyorixClient client(HttpServer s) throws KeyorixException {
        return Keyorix.newClient(url(s), "tok");
    }

    @Test
    void truncatedProjectListIsAnError() throws Exception {
        HttpServer s = serve(200, "{\"success\":true,\"data\":{\"projects\":[{\"id\":1,\"name\":\"a\"},{\"id\":2,\"na");
        try {
            assertThrows(KeyorixException.class, () -> client(s).listProjects());
        } finally {
            s.stop(0);
        }
    }

    @Test
    void projectWithAnOverflowingIdIsNotDropped() throws Exception {
        HttpServer s = serve(200, "{\"success\":true,\"data\":{\"projects\":[{\"id\":1,\"name\":\"a\"},"
            + "{\"id\":99999999999999999999,\"name\":\"b\"}]}}");
        try {
            assertThrows(KeyorixException.class, () -> client(s).listProjects());
        } finally {
            s.stop(0);
        }
    }

    @Test
    void secretReadWithoutAValueIsAnError() throws Exception {
        HttpServer s = serve(200, "{\"success\":true,\"data\":{}}");
        try {
            assertThrows(KeyorixException.class, () -> client(s).getSecretByRef("p/e/n"));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void secretReadReportingFailureIsAnError() throws Exception {
        HttpServer s = serve(200, "{\"success\":false,\"data\":{\"value\":\"v\"}}");
        try {
            assertThrows(KeyorixException.class, () -> client(s).getSecretByRef("p/e/n"));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void multiLineValueEndingInABackslashRoundTrips() throws Exception {
        String pem = "-----BEGIN KEY-----\nAAA\"BBB\\CCC\n-----END KEY-----\n\\";
        HttpServer s = serve(200, "{\"success\":true,\"data\":{\"value\":" + JsonParser.quote(pem) + "}}");
        try {
            assertEquals(pem, client(s).getSecretByRef("p/e/n"));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void loginWithTruncatedOrFailedBodyIsAnError() throws Exception {
        for (String body : new String[] {
            "{\"success\":true,\"data\":{\"token\":\"abc",
            "{\"success\":false,\"data\":{\"token\":\"abc\"}}",
            "{\"success\":true,\"data\":{\"token\":{\"x\":1}}}",
        }) {
            HttpServer s = serve(200, body);
            try {
                assertThrows(KeyorixException.class, () -> Keyorix.login(url(s), "u", "p"), body);
            } finally {
                s.stop(0);
            }
        }
    }

    @Test
    void errorStatusWithAnUnparseableOrEmptyBodyKeepsItsType() throws Exception {
        for (String body : new String[] {"", "<html>bad gateway</html>", "{\"error\":"}) {
            HttpServer s = serve(403, body);
            try {
                assertThrows(ForbiddenException.class, () -> client(s).listProjects(), "body: " + body);
            } finally {
                s.stop(0);
            }
        }
    }
}
