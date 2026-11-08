package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** String escaping on the way out (login body) and unescaping on the way in (parser). */
class JsonEscapeTest {

    @Test
    void extractStringUnescapesQuotesAndBackslashes() throws Exception {
        String json = "{\"data\":{\"name\":\"quote\\\"and\\\\back\"}}";
        assertEquals("quote\"and\\back", JsonParser.extractString(json, "name"));
    }

    @Test
    void extractStringStopsAtQuoteAfterEscapedBackslash() throws Exception {
        // value is a single backslash; the quote after the escaped backslash ends the string
        String json = "{\"data\":{\"a\":\"\\\\\",\"b\":\"next\"}}";
        assertEquals("\\", JsonParser.extractString(json, "a"));
        assertEquals("next", JsonParser.extractString(json, "b"));
    }

    @Test
    void extractStringDecodesControlAndUnicodeEscapes() throws Exception {
        String json = "{\"data\":{\"v\":\"l1\\nl2\\ttab\\u00e9\\/x\"}}";
        assertEquals("l1\nl2\ttabé/x", JsonParser.extractString(json, "v"));
    }

    @Test
    void loginEscapesControlCharactersSoTheBodyIsValidJson() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/auth/login", ex -> {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            ex.getRequestBody().transferTo(bo);
            body.set(new String(bo.toByteArray(), StandardCharsets.UTF_8));
            byte[] resp = "{\"data\":{\"token\":\"t\"}}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, resp.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();
        try {
            Keyorix.login("http://127.0.0.1:" + server.getAddress().getPort(), "u\tser", "pw\n\u0001\"\\");
        } catch (KeyorixException e) {
            // the response shape is not under test; only the request body is
        } finally {
            server.stop(0);
        }
        assertEquals("{\"username\":\"u\\tser\",\"password\":\"pw\\n\\u0001\\\"\\\\\"}", body.get());
    }
}
