package com.keyorix;

/** Base exception for all Keyorix SDK errors. */
public class KeyorixException extends Exception {
    public KeyorixException(String message) { super(message); }
    public KeyorixException(String message, Throwable cause) { super(message, cause); }
}
