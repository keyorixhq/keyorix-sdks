package com.keyorix;

/**
 * Thrown by {@link KeyorixClient#createSecret} when a live secret of that name
 * already exists in the project and environment (HTTP 409, error code
 * {@code ConflictError}). Carries no secret value.
 */
public class SecretAlreadyExistsException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public SecretAlreadyExistsException(String message, int statusCode, String responseBody, String errorCode) { super(message, statusCode, responseBody, errorCode); }
}
