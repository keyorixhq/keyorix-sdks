package com.keyorix;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Contract test: exercises this SDK's public API against a REAL, running
 * keyorix-server -- not a mock -- to prove the SDK's wire-format assumptions
 * (the JSON keys {@link JsonParser} reads) still match the actual API on
 * keyorixhq/keyorix's main branch. Every case here is green on main today
 * (verified against a local keyorix-server built from main, 2026-09-25); its
 * purpose is to go RED the moment a server-side change (e.g. a wire-format
 * migration to snake_case for a type this SDK parses) lands without a
 * matching SDK update.
 *
 * <p>Self-contained: bootstraps its own fresh admin account via /system/init,
 * so CI can run it against a bare {@code go run ./server} + SQLite, no
 * Docker/Postgres fixture required (see .github/workflows/contract.yml).
 *
 * <p>Note: this SDK has no {@code createProject} method (unlike the Go/Node/
 * Python SDKs in this repo -- see the keyorix repo's SDKS track report for
 * the full compatibility matrix), so this test exercises the read surface
 * against the bootstrap-seeded "default" project rather than a freshly
 * created one.
 *
 * <p>Skipped unless KEYORIX_CONTRACT_SERVER_URL is set.
 */
@EnabledIfEnvironmentVariable(named = "KEYORIX_CONTRACT_SERVER_URL", matches = ".+")
class ContractTest {

    private static String serverUrl;
    private static String token;
    private static KeyorixClient client;

    @BeforeAll
    static void bootstrap() throws Exception {
        serverUrl = System.getenv("KEYORIX_CONTRACT_SERVER_URL");
        String bootstrapToken = System.getenv("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN");
        if (bootstrapToken == null || bootstrapToken.isEmpty()) {
            throw new IllegalStateException("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL");
        }

        String initBody = "{\"username\":\"contract-admin\",\"email\":\"contract-admin@example.com\","
                + "\"password\":\"ContractTestPassw0rd!\",\"bootstrap_token\":\"" + bootstrapToken + "\"}";
        int status = postJson(serverUrl + "/system/init", initBody, null);
        if (status >= 300) {
            throw new IllegalStateException("POST /system/init: unexpected status " + status);
        }

        token = Keyorix.login(serverUrl, "contract-admin", "ContractTestPassw0rd!");
        client = Keyorix.newClient(serverUrl, token);
    }

    private static void seedSecret(long projectId, long environmentId, String name, String value) throws IOException {
        String body = "{\"name\":\"" + name + "\",\"value\":\"" + value + "\",\"project_id\":" + projectId
                + ",\"environment_id\":" + environmentId + ",\"type\":\"generic\"}";
        int status = postJson(serverUrl + "/api/v1/secrets", body, token);
        if (status >= 300) {
            throw new IllegalStateException("POST /api/v1/secrets: unexpected status " + status);
        }
    }

    private static int postJson(String url, String body, String bearerToken) throws IOException {
        return postJson(url, body, bearerToken, null);
    }

    private static int postJson(String url, String body, String bearerToken, StringBuilder responseOut) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        if (bearerToken != null) {
            conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int status = conn.getResponseCode();
        InputStream is = status >= 300 ? conn.getErrorStream() : conn.getInputStream();
        if (is != null) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = is.read(chunk)) != -1) buf.write(chunk, 0, n);
            if (responseOut != null) responseOut.append(buf.toString(StandardCharsets.UTF_8));
        }
        conn.disconnect();
        return status;
    }

    private static int getStatus(String url, String bearerToken) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
        int status = conn.getResponseCode();
        conn.disconnect();
        return status;
    }

    /** Mints a personal access token for the caller identified by adminToken, via raw
     * HTTP (PAT issuance is not part of this SDK's public surface). */
    private static String createPAT(String adminToken, String name) throws IOException {
        StringBuilder resp = new StringBuilder();
        int status = postJson(serverUrl + "/api/v1/auth/tokens", "{\"name\":\"" + name + "\"}", adminToken, resp);
        if (status >= 300) {
            throw new IllegalStateException("POST /api/v1/auth/tokens: unexpected status " + status);
        }
        String tok = JsonParser.extractString(resp.toString(), "token");
        if (tok == null) throw new IllegalStateException("create-PAT response had no token");
        return tok;
    }

    /** Creates a fresh machine identity in projectId and issues it a token, via raw HTTP
     * (neither is part of this SDK's public surface). A brand-new machine identity holds
     * no roles, so this token authenticates but is not authorized for anything yet --
     * exactly the shape needed to prove authentication succeeds independently of
     * authorization. */
    private static String createMachineToken(String adminToken, long projectId) throws IOException {
        StringBuilder idResp = new StringBuilder();
        String idBody = "{\"name\":\"contract-test-machine-" + System.nanoTime() + "\",\"identity_type\":\"service\"}";
        int idStatus = postJson(serverUrl + "/api/v1/projects/" + projectId + "/machine-identities", idBody, adminToken, idResp);
        if (idStatus >= 300) {
            throw new IllegalStateException("POST machine-identities: unexpected status " + idStatus);
        }
        long machineId = parseIdField(idResp.toString());
        if (machineId == 0) throw new IllegalStateException("create-machine-identity response had no id");

        StringBuilder tokResp = new StringBuilder();
        int tokStatus = postJson(
            serverUrl + "/api/v1/projects/" + projectId + "/machine-identities/" + machineId + "/tokens",
            "{\"name\":\"contract-test-machine-token\"}", adminToken, tokResp);
        if (tokStatus >= 300) {
            throw new IllegalStateException("POST machine-identities tokens: unexpected status " + tokStatus);
        }
        String tok = JsonParser.extractString(tokResp.toString(), "token");
        if (tok == null) throw new IllegalStateException("issue-machine-token response had no token");
        return tok;
    }

    /** Extracts the raw numeric "id" field nested under "machine_identity" in a
     * create-machine-identity response, e.g. {"data":{"machine_identity":{"id":1,...}}}. */
    private static long parseIdField(String json) {
        int idx = json.indexOf("\"machine_identity\"");
        if (idx == -1) return 0;
        int idIdx = json.indexOf("\"id\"", idx);
        if (idIdx == -1) return 0;
        int colon = json.indexOf(':', idIdx);
        int start = colon + 1;
        int end = start;
        while (end < json.length() && Character.isDigit(json.charAt(end))) end++;
        if (start == end) return 0;
        return Long.parseLong(json.substring(start, end));
    }

    @Test
    void health() throws KeyorixException {
        assertTrue(client.health());
    }

    @Test
    void listProjectsFindsDefault() throws KeyorixException {
        List<Project> projects = client.listProjects();
        Project defaultProject = projects.stream().filter(p -> p.getName().equals("default")).findFirst().orElse(null);
        assertNotNull(defaultProject, "expected a 'default' project");
    }

    @Test
    void listEnvironmentsReturnsSeededTrio() throws KeyorixException {
        Project defaultProject = client.listProjects().stream()
                .filter(p -> p.getName().equals("default")).findFirst().orElseThrow();
        List<Environment> envs = client.listEnvironments(defaultProject.getId());
        List<String> names = envs.stream().map(Environment::getName).sorted().collect(java.util.stream.Collectors.toList());
        assertEquals(List.of("development", "production", "staging"), names);
        for (Environment e : envs) {
            assertEquals(defaultProject.getId(), e.getProjectId());
        }
    }

    @Test
    void secretRoundTripsValue() throws Exception {
        Project defaultProject = client.listProjects().stream()
                .filter(p -> p.getName().equals("default")).findFirst().orElseThrow();
        Environment devEnv = client.listEnvironments(defaultProject.getId()).stream()
                .filter(e -> e.getName().equals("development")).findFirst().orElseThrow();

        String secretName = "contract-test-secret-" + System.nanoTime();
        String secretValue = "contract-test-value-do-not-use";
        seedSecret(defaultProject.getId(), devEnv.getId(), secretName, secretValue);

        List<Secret> secrets = client.listSecretsScoped(defaultProject.getId(), devEnv.getId());
        Secret found = secrets.stream().filter(s -> s.getName().equals(secretName)).findFirst().orElse(null);
        assertNotNull(found, "expected to find seeded secret " + secretName);
        assertEquals(defaultProject.getId(), found.getProjectId());

        String value = client.getSecretScoped(secretName, defaultProject.getId(), devEnv.getId());
        assertEquals(secretValue, value);
    }

    @Test
    void createProjectRoundTrips() throws Exception {
        String name = "contract-test-project-" + System.nanoTime();
        Project p = client.createProject(name, "created by the Java SDK contract test");
        assertEquals(name, p.getName());
        assertEquals("created by the Java SDK contract test", p.getDescription());
        assertTrue(p.getId() > 0, "createProject returns a nonzero id");
        assertTrue(client.listProjects().stream().anyMatch(x -> x.getId() == p.getId()),
                "created project appears in listProjects");
    }

    @Test
    void createSecretReadsBack() throws Exception {
        String name = "contract-create-" + System.nanoTime();
        String value = "contract-create-value-do-not-use";
        Secret created = client.createSecret("default", "development", name, value,
                "generic", "created by the Java SDK contract test");
        assertTrue(created.getId() > 0);
        assertEquals(name, created.getName());
        assertEquals("generic", created.getType());
        assertEquals(value, client.getSecretScoped(name, "default", "development"));
        assertTrue(client.listSecretsScoped("default", "development").stream().anyMatch(s -> s.getId() == created.getId()),
                "created secret appears in listSecretsScoped");
    }

    @Test
    void createSecretDuplicateNameIsTyped() throws Exception {
        String name = "contract-create-dup-" + System.nanoTime();
        String value = "contract-create-value-do-not-use";
        client.createSecret("default", "development", name, value);
        SecretAlreadyExistsException e = assertThrows(SecretAlreadyExistsException.class,
                () -> client.createSecret("default", "development", name, value));
        assertEquals(409, e.getStatusCode());
        assertFalse(String.valueOf(e.getMessage()).contains(value));
        assertFalse(String.valueOf(e.getResponseBody()).contains(value));
    }

    @Test
    void createSecretUnauthenticatedIsAuthException() throws Exception {
        long projectId = client.listProjects().stream().filter(p -> "default".equals(p.getName())).findFirst().get().getId();
        long envId = client.listEnvironments(projectId).get(0).getId();
        // By ID, so the 401 comes from POST /api/v1/secrets itself and not from
        // the project lookup a by-name call does first.
        for (String badToken : new String[] {"not-a-valid-token", ""}) {
            KeyorixClient bad = Keyorix.newClient(serverUrl, badToken);
            assertThrows(AuthException.class,
                    () -> bad.createSecret(projectId, envId, "contract-create-anon", "v", null, null),
                    "token '" + badToken + "'");
        }
    }

    @Test
    void deletedSecretExposesPurgeAt() throws Exception {
        Project defaultProject = client.listProjects().stream()
                .filter(p -> p.getName().equals("default")).findFirst().orElseThrow();
        Environment devEnv = client.listEnvironments(defaultProject.getId()).stream()
                .filter(e -> e.getName().equals("development")).findFirst().orElseThrow();
        String name = "contract-purge-" + System.nanoTime();
        seedSecret(defaultProject.getId(), devEnv.getId(), name, "v");
        Secret live = client.listSecretsScoped(defaultProject.getId(), devEnv.getId()).stream()
                .filter(s -> s.getName().equals(name)).findFirst().orElseThrow();
        assertEquals("", live.getPurgeAt(), "a live secret has no purgeAt");

        // DELETE is not part of this SDK's public surface: raw HTTP.
        HttpURLConnection conn = (HttpURLConnection) new URL(serverUrl + "/api/v1/secrets/" + live.getId()).openConnection();
        conn.setRequestMethod("DELETE");
        conn.setRequestProperty("Authorization", "Bearer " + token);
        assertEquals(204, conn.getResponseCode());
        conn.disconnect();

        Secret deleted = client.listDeletedSecrets(defaultProject.getId()).stream()
                .filter(s -> s.getId() == live.getId()).findFirst().orElse(null);
        assertNotNull(deleted, "soft-deleted secret missing from listDeletedSecrets");
        assertFalse(deleted.getPurgeAt().isEmpty(), "soft-deleted secret has no purgeAt");
        double days = java.time.Duration.between(java.time.Instant.now(), java.time.Instant.parse(deleted.getPurgeAt())).toSeconds() / 86400.0;
        assertTrue(days > 29 && days < 31, "purgeAt " + deleted.getPurgeAt() + " is not ~30 days out (retention_days=30)");
    }

    @Test
    void patAuthWorksTransparently() throws Exception {
        String pat = createPAT(token, "contract-test-pat");
        KeyorixClient patClient = Keyorix.newClient(serverUrl, pat);
        assertDoesNotThrow(patClient::listProjects,
            "Client with a PAT should succeed -- a PAT presents identically to a session token");
    }

    @Test
    void listProjectsSucceedsWithEmptyListForZeroGrantToken() throws Exception {
        Project defaultProject = client.listProjects().stream()
                .filter(p -> p.getName().equals("default")).findFirst().orElseThrow();
        String machineToken = createMachineToken(token, defaultProject.getId());
        KeyorixClient machineClient = Keyorix.newClient(serverUrl, machineToken);
        // A brand-new machine identity holds no roles. List routes are filtered by
        // permission, so it authenticates and gets an EMPTY 200 (not AuthException,
        // not ForbiddenException).
        assertTrue(machineClient.listProjects().isEmpty(),
            "expected an empty project list for a zero-grant token");
    }

    @Test
    void getProjectWithZeroGrantTokenIsForbidden() throws Exception {
        Project defaultProject = client.listProjects().stream()
                .filter(p -> p.getName().equals("default")).findFirst().orElseThrow();
        String machineToken = createMachineToken(token, defaultProject.getId());
        assertEquals(403, getStatus(serverUrl + "/api/v1/projects/" + defaultProject.getId(), machineToken),
            "GET /projects/{id} with a zero-grant token must be forbidden (403)");
    }

    @Test
    void listProjectsWithBadTokenIsUnauthorized() throws Exception {
        KeyorixClient badClient = Keyorix.newClient(serverUrl, "not-a-valid-token");
        assertThrows(AuthException.class, badClient::listProjects);
    }

    @Test
    void timeoutIsEnforcedAgainstASlowServer() throws Exception {
        com.sun.net.httpserver.HttpServer slow =
            com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("localhost", 0), 0);
        // The handler blocks on a latch (released in the finally below) instead
        // of sleeping a fixed time, so the server is "slow" for exactly as long
        // as the client's 10ms timeout needs -- no timing race, no Thread.sleep.
        CountDownLatch release = new CountDownLatch(1);
        slow.createContext("/", exchange -> {
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            byte[] resp = "{\"data\":{\"projects\":[]}}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        slow.start();
        try {
            KeyorixClient slowClient = new KeyorixClient(
                "http://localhost:" + slow.getAddress().getPort(), "tok", java.time.Duration.ofMillis(10));
            assertThrows(KeyorixException.class, slowClient::listProjects,
                "expected a timeout error from a 10ms client against a stalled server");
        } finally {
            release.countDown();
            slow.stop(0);
        }
    }
}
