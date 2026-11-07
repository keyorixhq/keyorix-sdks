package com.keyorix;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** A server URL given with trailing slashes must not yield "//..." request paths. */
class TrailingSlashTest {

    @Test
    void healthRequestPathHasNoDuplicateSlashes() throws Exception {
        AtomicReference<String> path = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", ex -> {
            path.set(ex.getRequestURI().getRawPath());
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        try {
            for (String suffix : new String[] {"/", "//"}) {
                KeyorixClient c = new KeyorixClient("http://localhost:" + server.getAddress().getPort() + suffix, "t");
                path.set(null);
                c.health();
                assertEquals("/health", path.get(), "suffix '" + suffix + "'");
            }
        } finally {
            server.stop(0);
        }
    }
}
