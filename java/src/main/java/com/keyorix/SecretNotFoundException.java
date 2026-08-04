package com.keyorix;

/** Thrown when a secret cannot be found. */
public class SecretNotFoundException extends KeyorixException {
    private static final long serialVersionUID = 1L;
    public SecretNotFoundException(String message) { super(message); }
}
