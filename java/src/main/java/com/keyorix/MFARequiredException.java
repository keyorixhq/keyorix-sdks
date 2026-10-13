package com.keyorix;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Thrown by {@link Keyorix#login} when the password was accepted but the account
 * has a second factor, so the server answered with an MFA challenge instead of a
 * session. Still an {@link AuthException} ({@code login} used to throw a generic
 * one here), so existing {@code catch (AuthException e)} handlers keep working.
 *
 * <p>Complete the login with {@link Keyorix#verifyMfa}, passing
 * {@link #getChallenge()} and a current TOTP (or recovery) code. The challenge is
 * single-use and short-lived. {@link #getMethods()} lists the account's second
 * factors ("totp", "webauthn"); this SDK completes only TOTP or recovery codes, a
 * passkey needs a browser ceremony.
 */
public class MFARequiredException extends AuthException {
    private static final long serialVersionUID = 1L;

    private final String challenge;
    private final boolean totpAvailable;
    private final boolean webauthnAvailable;

    public MFARequiredException(String challenge, boolean totpAvailable, boolean webauthnAvailable) {
        super("Multi-factor authentication required — complete the login with Keyorix.verifyMfa()");
        this.challenge = challenge;
        this.totpAvailable = totpAvailable;
        this.webauthnAvailable = webauthnAvailable;
    }

    /** The single-use challenge id to pass to {@link Keyorix#verifyMfa}. */
    public String getChallenge() { return challenge; }

    public boolean isTotpAvailable() { return totpAvailable; }

    public boolean isWebauthnAvailable() { return webauthnAvailable; }

    /** The second factors the account has: "totp" and/or "webauthn". */
    public List<String> getMethods() {
        List<String> m = new ArrayList<>();
        if (totpAvailable) m.add("totp");
        if (webauthnAvailable) m.add("webauthn");
        return Collections.unmodifiableList(m);
    }
}
