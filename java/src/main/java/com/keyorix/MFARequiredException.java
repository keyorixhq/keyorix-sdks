package com.keyorix;

/**
 * Thrown by {@link Keyorix#login} when the password was correct but the account
 * needs a second factor. The server answers 200 with {@code mfa_required} and a
 * single-use challenge instead of a session token: pass {@link #getChallenge()}
 * and a TOTP (or recovery) code to {@link Keyorix#verifyMfa}, or use
 * {@link Keyorix#login(String, String, String, String)} with the code up front.
 */
public class MFARequiredException extends KeyorixException {
    private static final long serialVersionUID = 1L;

    private final String challenge;
    private final boolean totpAvailable;
    private final boolean webauthnAvailable;

    public MFARequiredException(String challenge, boolean totpAvailable, boolean webauthnAvailable) {
        super("Multi-factor authentication required — call Keyorix.verifyMfa() with the challenge and a TOTP or recovery code");
        this.challenge = challenge;
        this.totpAvailable = totpAvailable;
        this.webauthnAvailable = webauthnAvailable;
    }

    /** Single-use token to pass to {@link Keyorix#verifyMfa}. */
    public String getChallenge() { return challenge; }

    /** The account can complete the challenge with a TOTP or recovery code. */
    public boolean isTotpAvailable() { return totpAvailable; }

    /** The account can complete the challenge with a passkey (not supported by this SDK). */
    public boolean isWebauthnAvailable() { return webauthnAvailable; }
}
