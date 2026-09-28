package com.keyorix;

/**
 * Thrown when a requested resource does not exist on the server (HTTP 404).
 * Distinct from {@link SecretNotFoundException}, which is thrown by
 * name-based resolution before any such request is made.
 */
public class NotFoundException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public NotFoundException(String message) { super(message); }
    public NotFoundException(String message, int statusCode, String responseBody) { super(message, statusCode, responseBody); }
}
