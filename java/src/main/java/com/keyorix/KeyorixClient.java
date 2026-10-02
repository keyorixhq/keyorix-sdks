package com.keyorix;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Keyorix Java SDK — client for the Keyorix secrets manager API.
 *
 * <p>Zero external dependencies. Uses Java standard library only (Java 11+).
 *
 * <p>Quick start, for a machine identity token (the recommended credential
 * for an unattended application — see the README):
 * <pre>
 *   KeyorixClient client = new KeyorixClient("https://your-server:8443", System.getenv("KEYORIX_TOKEN"));
 *   String dbPassword = client.getSecretIn("my-project", "production", "db-password");
 * </pre>
 *
 * <p>{@code getSecretIn}/{@code getSecretByRef} resolve and authorize in one
 * round trip and need no project/environment-list permission.
 * {@code getSecretScoped}/{@code listSecretsScoped} are the alternative when
 * you already have (or want to cache) project/environment IDs rather than
 * names.
 */
public class KeyorixClient {

    private static final String SECRETS_PATH = "/api/v1/secrets";
    private static final String SECRETS_VALUE_PATH = "/api/v1/secrets/value";
    private static final String PROJECTS_PATH = "/api/v1/projects";
    private static final String HEALTH_PATH = "/health";

    private final String baseUrl;
    private final String token;
    private final int timeoutMs;
    private final SSLSocketFactory sslSocketFactory;

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
        this(baseUrl, token, timeout, null);
    }

    /**
     * Creates a new KeyorixClient trusting a private/internal CA, for
     * servers whose certificate isn't signed by a CA in the JVM's default
     * trust store. No effect on plain http:// (loopback-only) connections.
     *
     * @param baseUrl    Base URL of your Keyorix server; must use https:// (http://
     *                   is only accepted for localhost/loopback)
     * @param token      Session token
     * @param timeout    Request timeout
     * @param caCertPath Path to a PEM-encoded CA certificate to trust, or null
     *                   to use the JVM's default trust store
     * @throws KeyorixException if baseUrl is invalid, uses a disallowed scheme,
     *                          or caCertPath cannot be read/parsed
     */
    public KeyorixClient(String baseUrl, String token, Duration timeout, String caCertPath) throws KeyorixException {
        validateServerUrl(baseUrl);
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.token = token;
        this.timeoutMs = (int) timeout.toMillis();
        this.sslSocketFactory = caCertPath == null ? null : buildSslSocketFactory(caCertPath);
    }

    private static SSLSocketFactory buildSslSocketFactory(String caCertPath) throws KeyorixException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate ca;
            try (FileInputStream fis = new FileInputStream(caCertPath)) {
                ca = cf.generateCertificate(fis);
            }
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new KeyorixException("Failed to load CA certificate '" + caCertPath + "': " + e.getMessage(), e);
        }
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
     * project/environment name resolution round trip is made. Follows
     * every page the server reports (total_pages) at page_size=100, so a
     * scope with more secrets than fit on one page (the server defaults to
     * 20) is never silently truncated.
     *
     * @throws KeyorixException if an API error occurs
     */
    public List<Secret> listSecretsScoped(long projectId, long environmentId) throws KeyorixException {
        List<Secret> all = new ArrayList<>();
        int page = 1;
        while (true) {
            String path = SECRETS_PATH + "?project_id=" + projectId + "&environment_id=" + environmentId
                + "&page=" + page + "&page_size=100";
            String response = get(path);
            all.addAll(JsonParser.parseSecretList(response));
            int totalPages = JsonParser.parseTotalPages(response);
            if (page >= totalPages) break;
            page++;
        }
        return all;
    }

    /**
     * Returns the value of secret {@code name} within {@code project}/
     * {@code environment}, all by name, via a single server-authorized
     * round trip — a thin wrapper around {@link #getSecretByRef(String)}.
     * Unlike {@code getSecretScoped}, this needs no project/environment-list
     * permission, since the server resolves and authorizes the whole
     * reference itself. project/environment/name are joined with "/" — if
     * any contains a literal "/", call {@link #getSecretByRef(String)}
     * directly with your own escaping.
     *
     * @throws KeyorixException if an API error occurs
     */
    public String getSecretIn(String project, String environment, String name) throws KeyorixException {
        return getSecretByRef(project + "/" + environment + "/" + name);
    }

    /**
     * Returns a secret's value by its "project/environment/name" reference,
     * via {@code GET /api/v1/secrets/value?ref=<ref>}. The server resolves
     * and authorizes ref against the resolved secret's own scope in one
     * round trip — no project/environment-list permission needed, unlike
     * {@code getSecretScoped}. The secret name may itself contain "/"; only
     * the first two "/"-separated segments of ref are taken as project and
     * environment.
     *
     * <p>Throws {@link NotFoundException} if ref resolves to nothing and the
     * caller holds the global permission needed to confirm that; otherwise
     * (including when ref resolves to nothing and the caller does NOT hold
     * that permission — the server denies without confirming the resource
     * exists, to avoid existence enumeration) a {@link ForbiddenException}.
     * A malformed ref (not "project/environment/name") or an
     * {@link AuthException} follow the same mapping as every other call —
     * see {@link #mapError}.
     *
     * @throws KeyorixException if an API error occurs
     */
    public String getSecretByRef(String ref) throws KeyorixException {
        String encoded = java.net.URLEncoder.encode(ref, StandardCharsets.UTF_8);
        String response = get(SECRETS_VALUE_PATH + "?ref=" + encoded);
        return JsonParser.parseSecretValue(response);
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
            if (status != 200) {
                String body = readStream(conn.getErrorStream());
                throw mapError(status, body);
            }
            String body = readStream(conn.getInputStream());
            conn.disconnect();
            return body;
        } catch (IOException e) {
            throw new KeyorixException("Request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Maps a non-2xx HTTP status to a typed exception: AuthException (401),
     * ForbiddenException (403), NotFoundException (404), or the generic
     * KeyorixException for anything else. Every request path throws through
     * this so callers can catch the specific type they need, regardless of
     * which method failed.
     */
    private static KeyorixException mapError(int status, String body) {
        switch (status) {
            case 401:
                return new AuthException("Unauthorized — check your token", status, body);
            case 403:
                return new ForbiddenException("Forbidden — token lacks permission for this request", status, body);
            case 404:
                return new NotFoundException("Resource not found", status, body);
            default:
                return new KeyorixException("Server returned " + status, status, body);
        }
    }

    private HttpURLConnection openConnection(String url, String method, boolean auth) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        if (sslSocketFactory != null && conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setSSLSocketFactory(sslSocketFactory);
        }
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
