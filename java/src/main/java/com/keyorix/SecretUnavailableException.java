package com.keyorix;

/**
 * Thrown when the token may read the secret but the secret's own state refuses
 * the value read (HTTP 409): it has expired, is suspended, or has used up its
 * max-reads budget. {@link #getErrorCode()} says which; each is reversible by an
 * operator.
 */
public class SecretUnavailableException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public SecretUnavailableException(String message, int statusCode, String responseBody, String errorCode) { super(message, statusCode, responseBody, errorCode); }
}
