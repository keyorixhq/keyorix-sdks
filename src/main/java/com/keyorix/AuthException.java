package com.keyorix;

/** Thrown when authentication fails. */
public class AuthException extends KeyorixException {
    public AuthException(String message) { super(message); }
}
