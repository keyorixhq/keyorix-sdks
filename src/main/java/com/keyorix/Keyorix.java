package com.keyorix;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Factory class and entry point for the Keyorix Java SDK.
 *
 * <pre>
 *   String token = Keyorix.login("http://localhost:8080", "admin", "password");
 *   KeyorixClient client = Keyorix.newClient("http://localhost:8080", token);
 *   String secret = client.getSecret("db-password", "production");
 * </pre>
 */
public final class Keyorix {

    private Keyorix() {}

    /**
     * Authenticates with the Keyorix server and returns a session token.
     *
     * @param serverUrl Base URL of your Keyorix server
     * @param username  Username
     * @param password  Password
     * @return Session token
     * @throws AuthException    if authentication fails
     * @throws KeyorixException on other errors
     */
    public static String login(String serverUrl, String username, String password) throws KeyorixException {
        return login(serverUrl, username, password, Duration.ofSeconds(30));
    }

    /**
     * Authenticates with the Keyorix server and returns a session token.
     */
    public static String login(String serverUrl, String username, String password, Duration timeout) throws KeyorixException {
        String url = serverUrl.replaceAll("/$", "") + "/auth/login";
        String body = "{\"username\":\"" + escape(username) + "\",\"password\":\"" + escape(password) + "\"}";

        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout((int) timeout.toMillis());
            conn.setReadTimeout((int) timeout.toMillis());
            conn.setRequestProperty("Content-Type", "application/json");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            int status = conn.getResponseCode();
            byte[] buf = (status == 200 ? conn.getInputStream() : conn.getErrorStream()).readAllBytes();
            String response = new String(buf, StandardCharsets.UTF_8);
            conn.disconnect();

            if (status != 200) {
                throw new AuthException("Login failed (HTTP " + status + "): " + response);
            }

            String token = JsonParser.parseToken(response);
            if (token == null || token.isEmpty()) {
                throw new AuthException("No token in login response");
            }
            return token;

        } catch (IOException e) {
            throw new KeyorixException("Login request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a new {@link KeyorixClient}.
     */
    public static KeyorixClient newClient(String serverUrl, String token) {
        return new KeyorixClient(serverUrl, token);
    }

    /**
     * Creates a new {@link KeyorixClient} with a custom timeout.
     */
    public static KeyorixClient newClient(String serverUrl, String token, Duration timeout) {
        return new KeyorixClient(serverUrl, token, timeout);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
