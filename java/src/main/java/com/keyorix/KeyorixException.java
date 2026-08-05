package com.keyorix;

/**
 * Base exception for all Keyorix SDK errors.
 *
 * <p>The exception message deliberately omits the raw response body: it's
 * server-controlled content that this SDK's own README quick-start passes
 * straight to a bare {@code catch (KeyorixException e) { e.printStackTrace(); }},
 * and an unconditional relay into that path is exactly how untrusted content
 * ends up verbatim in application logs. Callers who need the body for their
 * own (redacted) logging can call {@link #getResponseBody()} directly.
 */
public class KeyorixException extends Exception {
    private static final long serialVersionUID = 1L;

    private final Integer statusCode;
    private final String responseBody;

    public KeyorixException(String message) {
        this(message, null, null, null);
    }

    public KeyorixException(String message, Throwable cause) {
        this(message, cause, null, null);
    }

    public KeyorixException(String message, int statusCode, String responseBody) {
        this(message, null, statusCode, responseBody);
    }

    private KeyorixException(String message, Throwable cause, Integer statusCode, String responseBody) {
        super(message, cause);
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }

    /** HTTP status code that caused this exception, or null if not applicable. */
    public Integer getStatusCode() { return statusCode; }

    /** Raw server response body that caused this exception, or null if not applicable. */
    public String getResponseBody() { return responseBody; }
}
