package com.keyorix;

/** Thrown when the server rejects a request as unauthorized for this token's permissions (HTTP 403). */
public class ForbiddenException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public ForbiddenException(String message) { super(message); }
    public ForbiddenException(String message, int statusCode, String responseBody) { super(message, statusCode, responseBody); }
}
