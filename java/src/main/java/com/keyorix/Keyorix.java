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

    private static final String LOGIN_PATH = "/auth/login";
    private static final String MFA_VERIFY_PATH = "/auth/mfa/verify";

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
     *
     * @throws MFARequiredException if the account has MFA enabled; complete the
     *                              login with {@link #verifyMfa}
     */
    public static String login(String serverUrl, String username, String password, Duration timeout) throws KeyorixException {
        return postLogin(serverUrl, LOGIN_PATH,
                "{\"username\":\"" + escape(username) + "\",\"password\":\"" + escape(password) + "\"}", timeout);
    }

    /**
     * Authenticates and, when the account has MFA enabled, completes the second
     * step with {@code mfaCode} (a current TOTP code or an unused recovery code).
     * Accounts without MFA ignore {@code mfaCode}.
     *
     * @throws AuthException if the password or the code is wrong
     */
    public static String login(String serverUrl, String username, String password, String mfaCode) throws KeyorixException {
        try {
            return login(serverUrl, username, password, Duration.ofSeconds(30));
        } catch (MFARequiredException e) {
            return verifyMfa(serverUrl, e.getChallenge(), mfaCode);
        }
    }

    /**
     * Completes a login that threw {@link MFARequiredException} and returns the
     * session token.
     *
     * @param challenge {@link MFARequiredException#getChallenge()} (single use)
     * @param code      current TOTP code, or an unused recovery code
     * @throws AuthException if the code or challenge is wrong or expired
     */
    public static String verifyMfa(String serverUrl, String challenge, String code) throws KeyorixException {
        return verifyMfa(serverUrl, challenge, code, Duration.ofSeconds(30));
    }

    public static String verifyMfa(String serverUrl, String challenge, String code, Duration timeout) throws KeyorixException {
        return postLogin(serverUrl, MFA_VERIFY_PATH,
                "{\"mfa_challenge\":\"" + escape(challenge) + "\",\"code\":\"" + escape(code) + "\"}", timeout);
    }

    private static String postLogin(String serverUrl, String path, String body, Duration timeout) throws KeyorixException {
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
                throw new AuthException("Login failed (HTTP " + status + ")", status, response);
            }

            if (JsonParser.extractBoolean(response, "mfa_required")) {
                throw new MFARequiredException(JsonParser.extractString(response, "mfa_challenge"),
                        JsonParser.extractBoolean(response, "totp_available"),
                        JsonParser.extractBoolean(response, "webauthn_available"));
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
