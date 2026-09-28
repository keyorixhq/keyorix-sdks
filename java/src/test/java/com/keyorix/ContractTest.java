package com.keyorix;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
        }
        conn.disconnect();
        return status;
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
}
