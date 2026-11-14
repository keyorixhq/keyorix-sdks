package com.keyorix;

/**
 * Thrown when the server refused a write (HTTP 503, code {@code audit_unavailable})
 * because the audit log could not record it. Nothing was changed, so the same
 * request is safe to retry unchanged later. The {@code Retry-After} header is not
 * surfaced.
 */
public class AuditUnavailableException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public AuditUnavailableException(String message, int statusCode, String responseBody, String errorCode) { super(message, statusCode, responseBody, errorCode); }
}
