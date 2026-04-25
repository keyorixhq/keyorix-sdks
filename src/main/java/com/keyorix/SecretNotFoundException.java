package com.keyorix;

/** Thrown when a secret cannot be found. */
public class SecretNotFoundException extends KeyorixException {
    public SecretNotFoundException(String message) { super(message); }
}
