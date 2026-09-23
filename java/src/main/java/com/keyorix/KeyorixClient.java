package com.keyorix;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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
 *   String token = Keyorix.login("https://your-server:8443", "admin", "password");
 *   KeyorixClient client = new KeyorixClient("https://your-server:8443", token);
 *   String dbPassword = client.getSecret("db-password", "production");
 * </pre>
 */
public class KeyorixClient {

    private static final String SECRETS_PATH = "/api/v1/secrets";
    private static final String HEALTH_PATH = "/health";

    private final String baseUrl;
    private final String token;
    private final int timeoutMs;

    /**
     * Creates a new KeyorixClient.
     *
     * @param baseUrl  Base URL of your Keyorix server; must use https:// (http://
     *                 is only accepted for localhost/loopback)
     * @param token    Session token obtained via {@link Keyorix#login}
     * @throws KeyorixException if baseUrl is invalid or uses a disallowed scheme
     */
    public KeyorixClient(String baseUrl, String token) throws KeyorixException {
        this(baseUrl, token, Duration.ofSeconds(30));
    }

    /**
     * Creates a new KeyorixClient with a custom timeout.
     *
     * @param baseUrl  Base URL of your Keyorix server; must use https:// (http://
     *                 is only accepted for localhost/loopback)
     * @param token    Session token
     * @param timeout  Request timeout
     * @throws KeyorixException if baseUrl is invalid or uses a disallowed scheme
     */
    public KeyorixClient(String baseUrl, String token, Duration timeout) throws KeyorixException {
        validateServerUrl(baseUrl);
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.token = token;
        this.timeoutMs = (int) timeout.toMillis();
    }

    /**
     * Rejects any scheme but https; allows http only for localhost/loopback. A
     * bearer token and every secret value would otherwise be sent/received in
     * cleartext, and an unrestricted scheme (e.g. file://) would let a
     * caller-influenced baseUrl reach something other than an HTTP server
     * entirely.
     */
    static void validateServerUrl(String serverUrl) throws KeyorixException {
        URI uri;
        try {
            uri = new URI(serverUrl);
        } catch (URISyntaxException e) {
            throw new KeyorixException("Invalid server URL '" + serverUrl + "': " + e.getMessage());
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
        if ("https".equals(scheme)) return;
        if ("http".equals(scheme) && isLoopbackHost(uri.getHost())) return;
        throw new KeyorixException(
            "Server URL '" + serverUrl + "' must use https:// (http:// is only allowed for localhost/loopback)");
    }

    private static boolean isLoopbackHost(String host) {
        if (host == null) return false;
        String h = host.toLowerCase();
        return h.equals("localhost") || h.equals("::1") || h.equals("[::1]")
            || h.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    }

    /**
     * Returns the plaintext value of a secret by name and environment.
     *
     * <p>environment is matched by name across every project the caller can
     * read, since this client has no project-scoped listing today — if the
     * SAME environment name (e.g. "production") exists in more than one
     * project and both contain a same-named secret, which one is returned is
     * unspecified.
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
     * Lists all secrets visible to the authenticated user, filtered by
     * environment name across every project.
     *
     * <p>An environment name is only unique WITHIN a project, not globally —
     * if two projects both have a "production" environment, this filters to
     * secrets in EITHER of them.
     *
     * <p>The server only recognizes {@code project_id}/{@code environment_id}
     * (numeric) as real filters — a bare {@code environment} name query
     * parameter is rejected with 400. This method filters by name
     * CLIENT-SIDE, after fetching the caller's full (unscoped) secret list,
     * so the {@code environment} argument's documented behavior actually
     * works, instead of previously being silently ignored server-side.
     *
     * @param environment Filter by environment name, or null/empty for all environments
     * @return List of secrets
     * @throws KeyorixException if an API error occurs
     */
    public List<Secret> listSecrets(String environment) throws KeyorixException {
        String response = get(SECRETS_PATH);
        List<Secret> secrets = JsonParser.parseSecretList(response);
        if (environment == null || environment.isEmpty()) {
            return secrets;
        }
        List<Secret> filtered = new ArrayList<>();
        for (Secret s : secrets) {
            if (environment.equals(s.getEnvironment())) {
                filtered.add(s);
            }
        }
        return filtered;
    }

    /**
     * Checks if the server is reachable and healthy.
     *
     * @return true if healthy
     * @throws KeyorixException if the server is unreachable or unhealthy
     */
    public boolean health() throws KeyorixException {
        try {
            HttpURLConnection conn = openConnection(baseUrl + HEALTH_PATH, "GET", false);
            int status = conn.getResponseCode();
            conn.disconnect();
            return status == 200;
        } catch (IOException e) {
            throw new KeyorixException("Server unreachable: " + e.getMessage(), e);
        }
    }

    private String fetchSecretValue(long secretId) throws KeyorixException {
        String response = get(SECRETS_PATH + "/" + secretId + "?include_value=true");
        return JsonParser.parseSecretValue(response);
    }

    private String get(String path) throws KeyorixException {
        try {
            HttpURLConnection conn = openConnection(baseUrl + path, "GET", true);
            int status = conn.getResponseCode();
            if (status == 401) throw new AuthException("Unauthorized — check your token");
            if (status != 200) {
                String body = readStream(conn.getErrorStream());
                throw new KeyorixException("Server returned " + status, status, body);
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
