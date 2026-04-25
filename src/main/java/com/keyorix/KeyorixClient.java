package com.keyorix;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Keyorix Java SDK — client for the Keyorix secrets manager API.
 *
 * <p>Zero external dependencies. Uses Java standard library only (Java 11+).
 *
 * <p>Quick start:
 * <pre>
 *   String token = Keyorix.login("http://your-server:8080", "admin", "password");
 *   KeyorixClient client = new KeyorixClient("http://your-server:8080", token);
 *   String dbPassword = client.getSecret("db-password", "production");
 * </pre>
 */
public class KeyorixClient {

    private final String baseUrl;
    private final String token;
    private final int timeoutMs;

    /**
     * Creates a new KeyorixClient.
     *
     * @param baseUrl  Base URL of your Keyorix server (e.g. "http://localhost:8080")
     * @param token    Session token obtained via {@link Keyorix#login}
     */
    public KeyorixClient(String baseUrl, String token) {
        this(baseUrl, token, Duration.ofSeconds(30));
    }

    /**
     * Creates a new KeyorixClient with a custom timeout.
     *
     * @param baseUrl  Base URL of your Keyorix server
     * @param token    Session token
     * @param timeout  Request timeout
     */
    public KeyorixClient(String baseUrl, String token, Duration timeout) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.token = token;
        this.timeoutMs = (int) timeout.toMillis();
    }

    /**
     * Returns the plaintext value of a secret by name and environment.
     *
     * @param name        Secret name
     * @param environment Environment name ("production", "staging", "development")
     * @return Plaintext secret value
     * @throws KeyorixException        if an API error occurs
     * @throws SecretNotFoundException if the secret is not found
     */
    public String getSecret(String name, String environment) throws KeyorixException {
        List<Secret> secrets = listSecrets(environment);
        for (Secret s : secrets) {
            if (name.equals(s.getName())) {
                return fetchSecretValue(s.getId());
            }
        }
        String envMsg = (environment != null && !environment.isEmpty()) ? " in environment '" + environment + "'" : "";
        throw new SecretNotFoundException("Secret '" + name + "' not found" + envMsg);
    }

    /**
     * Lists all secrets visible to the authenticated user.
     *
     * @param environment Filter by environment name, or null/empty for all environments
     * @return List of secrets
     * @throws KeyorixException if an API error occurs
     */
    public List<Secret> listSecrets(String environment) throws KeyorixException {
        String path = "/api/v1/secrets";
        if (environment != null && !environment.isEmpty()) {
            path += "?environment=" + URLEncoder.encode(environment, StandardCharsets.UTF_8);
        }
        String response = get(path);
        return JsonParser.parseSecretList(response);
    }

    /**
     * Checks if the server is reachable and healthy.
     *
     * @return true if healthy
     * @throws KeyorixException if the server is unreachable or unhealthy
     */
    public boolean health() throws KeyorixException {
        try {
            HttpURLConnection conn = openConnection(baseUrl + "/health", "GET", false);
            int status = conn.getResponseCode();
            conn.disconnect();
            return status == 200;
        } catch (IOException e) {
            throw new KeyorixException("Server unreachable: " + e.getMessage(), e);
        }
    }

    private String fetchSecretValue(long secretId) throws KeyorixException {
        String response = get("/api/v1/secrets/" + secretId + "?include_value=true");
        return JsonParser.parseSecretValue(response);
    }

    private String get(String path) throws KeyorixException {
        try {
            HttpURLConnection conn = openConnection(baseUrl + path, "GET", true);
            int status = conn.getResponseCode();
            if (status == 401) throw new AuthException("Unauthorized — check your token");
            if (status != 200) {
                String body = readStream(conn.getErrorStream());
                throw new KeyorixException("Server returned " + status + ": " + body);
            }
            String body = readStream(conn.getInputStream());
            conn.disconnect();
            return body;
        } catch (IOException e) {
            throw new KeyorixException("Request failed: " + e.getMessage(), e);
        }
    }

    private HttpURLConnection openConnection(String url, String method, boolean auth) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        if (auth) conn.setRequestProperty("Authorization", "Bearer " + token);
        return conn;
    }

    private static String readStream(InputStream is) throws IOException {
        if (is == null) return "";
        byte[] buf = is.readAllBytes();
        return new String(buf, StandardCharsets.UTF_8);
    }
}
