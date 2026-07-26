package com.keyorix;

/** Thrown when authentication fails. */
public class AuthException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public AuthException(String message) { super(message); }
}
