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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keyorix Java SDK — client for the Keyorix secrets manager API.
 *
 * <p>Zero external dependencies. Uses Java standard library only (Java 11+).
 *
 * <p>Quick start:
 * <pre>
 *   String token = Keyorix.login("https://your-server:8443", "admin", "password");
 *   KeyorixClient client = new KeyorixClient("https://your-server:8443", token);
 *   String dbPassword = client.getSecretScoped("db-password", "my-project", "production");
 * </pre>
 */
public class KeyorixClient {

    private static final String SECRETS_PATH = "/api/v1/secrets";
    private static final String PROJECTS_PATH = "/api/v1/projects";
    private static final String HEALTH_PATH = "/health";

    private final String baseUrl;
    private final String token;
    private final int timeoutMs;

    // Populated lazily by resolveProject/resolveEnvironment and never
    // invalidated for the lifetime of this client — a project/environment
    // rename mid-process is expected to be rare enough that a fresh client
    // is the right way to pick it up, not a cache-expiry policy.
    private final Map<String, Long> projectCache = new ConcurrentHashMap<>(); // lowercased name -> id
    private final Map<Long, Map<String, Long>> envCache = new ConcurrentHashMap<>(); // project id -> lowercased name -> id

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
     * @deprecated Removed since v0.3.0. An environment name is only unique
     * within one project, not globally, so scoping by environment alone
     * could silently resolve to another project's same-named secret.
     * Always throws without ever contacting the server (no silent fallback
     * to the old, unscoped behavior) — use
     * {@link #getSecretScoped(String, String, String)} instead.
     */
    @Deprecated
    public String getSecret(String name, String environment) throws KeyorixException {
        throw new KeyorixException(
            "getSecret(name, environment) was removed since v0.3.0 (an environment name is only "
                + "unique within one project, not globally) — use getSecretScoped(name, project, environment) instead");
    }

    /**
     * @deprecated Removed since v0.3.0. An environment name is only unique
     * within one project, not globally, so scoping by environment alone
     * could silently return secrets from every project the caller can
     * read. Always throws without ever contacting the server (no silent
     * fallback to the old, unscoped behavior) — use
     * {@link #listSecretsScoped(String, String)} instead.
     */
    @Deprecated
    public List<Secret> listSecrets(String environment) throws KeyorixException {
        throw new KeyorixException(
            "listSecrets(environment) was removed since v0.3.0 (an environment name is only "
                + "unique within one project, not globally) — use listSecretsScoped(project, environment) instead");
    }

    /**
     * Returns the plaintext value of the secret named {@code name} within
     * projectName's environmentName. {@code name} is matched exactly
     * (case-sensitive) among the secrets in that scope.
     *
     * @throws SecretNotFoundException   if no secret in scope has this name
     * @throws AmbiguousSecretException  if more than one secret in scope has
     *                                   this name — never guessed; see
     *                                   {@link AmbiguousSecretException#getIds()}
     * @throws KeyorixException          if an API error occurs
     */
    public String getSecretScoped(String name, String projectName, String environmentName) throws KeyorixException {
        long projectId = resolveProject(projectName);
        long envId = resolveEnvironment(projectId, environmentName);
        return getSecretScoped(name, projectId, envId);
    }

    /**
     * Returns the plaintext value of the secret named {@code name} within
     * projectId's environmentId — no project/environment name resolution
     * round trip is made.
     *
     * @throws SecretNotFoundException   if no secret in scope has this name
     * @throws AmbiguousSecretException  if more than one secret in scope has
     *                                   this name — never guessed; see
     *                                   {@link AmbiguousSecretException#getIds()}
     * @throws KeyorixException          if an API error occurs
     */
    public String getSecretScoped(String name, long projectId, long environmentId) throws KeyorixException {
        List<Secret> secrets = listSecretsScoped(projectId, environmentId);
        List<Secret> matches = new ArrayList<>();
        for (Secret s : secrets) {
            if (name.equals(s.getName())) matches.add(s);
        }
        if (matches.isEmpty()) {
            throw new SecretNotFoundException(
                "Secret '" + name + "' not found in project id=" + projectId + ", environment id=" + environmentId);
        }
        if (matches.size() > 1) {
            List<Long> ids = new ArrayList<>();
            for (Secret s : matches) ids.add(s.getId());
            throw new AmbiguousSecretException(
                "Secret '" + name + "' is ambiguous in project id=" + projectId + ", environment id="
                    + environmentId + ": matches IDs " + ids,
                ids);
        }
        return fetchSecretValue(matches.get(0).getId());
    }

    /**
     * Lists every secret within projectName's environmentName.
     *
     * @throws KeyorixException if an API error occurs
     */
    public List<Secret> listSecretsScoped(String projectName, String environmentName) throws KeyorixException {
        long projectId = resolveProject(projectName);
        long envId = resolveEnvironment(projectId, environmentName);
        return listSecretsScoped(projectId, envId);
    }

    /**
     * Lists every secret within projectId's environmentId — no
     * project/environment name resolution round trip is made.
     *
     * @throws KeyorixException if an API error occurs
     */
    public List<Secret> listSecretsScoped(long projectId, long environmentId) throws KeyorixException {
        String path = SECRETS_PATH + "?project_id=" + projectId + "&environment_id=" + environmentId;
        String response = get(path);
        return JsonParser.parseSecretList(response);
    }

    /**
     * Lists all projects visible to the authenticated user.
     *
     * @throws KeyorixException if an API error occurs
     */
    public List<Project> listProjects() throws KeyorixException {
        return JsonParser.parseProjectList(get(PROJECTS_PATH));
    }

    /**
     * Lists all environments for a project.
     *
     * @throws KeyorixException if an API error occurs
     */
    public List<Environment> listEnvironments(long projectId) throws KeyorixException {
        return JsonParser.parseEnvironmentList(get(PROJECTS_PATH + "/" + projectId + "/environments"));
    }

    /**
     * Resolves a project name to an ID, using (and populating) this
     * client's cache. Matched case-insensitively.
     */
    private long resolveProject(String projectName) throws KeyorixException {
        String key = projectName.toLowerCase();
        Long cached = projectCache.get(key);
        if (cached != null) return cached;

        for (Project p : listProjects()) {
            projectCache.put(p.getName().toLowerCase(), p.getId());
        }
        Long id = projectCache.get(key);
        if (id == null) {
            throw new KeyorixException("Project '" + projectName + "' not found");
        }
        return id;
    }

    /**
     * Resolves an environment name to an ID within projectId, using (and
     * populating) this client's per-project cache. Matched
     * case-insensitively.
     */
    private long resolveEnvironment(long projectId, String environmentName) throws KeyorixException {
        String key = environmentName.toLowerCase();
        Map<String, Long> byName = envCache.computeIfAbsent(projectId, id -> new ConcurrentHashMap<>());
        Long cached = byName.get(key);
        if (cached != null) return cached;

        for (Environment e : listEnvironments(projectId)) {
            byName.put(e.getName().toLowerCase(), e.getId());
        }
        Long id = byName.get(key);
        if (id == null) {
            throw new KeyorixException("Environment '" + environmentName + "' not found in project id=" + projectId);
        }
        return id;
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
