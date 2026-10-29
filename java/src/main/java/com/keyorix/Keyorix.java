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
 *   String secret = client.getSecretScoped("db-password", "my-project", "production");
 * </pre>
 */
public final class Keyorix {

    // Fixed routes of the Keyorix server's HTTP API (part of the wire contract,
    // not deployment configuration; the deployment-specific part is the
    // caller-supplied serverUrl). java:S1075 expects hardcoded URIs to be
    // configurable, which would only let a misconfiguration break every login.
    @SuppressWarnings("java:S1075")
    private static final String LOGIN_PATH = "/auth/login";
    @SuppressWarnings("java:S1075")
    private static final String VERIFY_MFA_PATH = "/auth/mfa/verify";

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
        String body = "{\"username\":\"" + escape(username) + "\",\"password\":\"" + escape(password) + "\"}";
        return authRequest(serverUrl, LOGIN_PATH, body, timeout, "Login");
    }

    /**
     * Completes a password login that threw {@link MFARequiredException}: exchanges
     * its challenge and a current TOTP (or recovery) code for a session token.
     *
     * @throws AuthException    if the code or challenge is wrong or expired
     * @throws KeyorixException on other errors
     */
    public static String verifyMfa(String serverUrl, String challenge, String code) throws KeyorixException {
        return verifyMfa(serverUrl, challenge, code, Duration.ofSeconds(30));
    }

    public static String verifyMfa(String serverUrl, String challenge, String code, Duration timeout) throws KeyorixException {
        String body = "{\"mfa_challenge\":\"" + escape(challenge) + "\",\"code\":\"" + escape(code) + "\"}";
        return authRequest(serverUrl, VERIFY_MFA_PATH, body, timeout, "MFA verify");
    }

    private static String authRequest(String serverUrl, String path, String body, Duration timeout, String what) throws KeyorixException {
        KeyorixClient.validateServerUrl(serverUrl);
        String url = serverUrl.replaceAll("/$", "") + path;

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
                throw new AuthException(what + " failed (HTTP " + status + ")", status, response,
                        JsonParser.extractString(response, "error"));
            }

            String token = JsonParser.parseToken(response);
            if (token != null && !token.isEmpty()) {
                return token;
            }
            String challenge = JsonParser.extractString(response, "mfa_challenge");
            if (JsonParser.extractBoolean(response, "mfa_required") && challenge != null && !challenge.isEmpty()) {
                throw new MFARequiredException(challenge,
                        JsonParser.extractBoolean(response, "totp_available"),
                        JsonParser.extractBoolean(response, "webauthn_available"));
            }
            throw new AuthException("No token in " + what.toLowerCase() + " response");

        } catch (IOException e) {
            throw new KeyorixException(what + " request failed: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a new {@link KeyorixClient}.
     */
    public static KeyorixClient newClient(String serverUrl, String token) throws KeyorixException {
        return new KeyorixClient(serverUrl, token);
    }

    /**
     * Creates a new {@link KeyorixClient} with a custom timeout.
     */
    public static KeyorixClient newClient(String serverUrl, String token, Duration timeout) throws KeyorixException {
        return new KeyorixClient(serverUrl, token, timeout);
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
