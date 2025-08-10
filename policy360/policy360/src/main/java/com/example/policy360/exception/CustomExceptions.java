package com.example.policy360.exception;

public abstract class CustomExceptions extends RuntimeException {

    public CustomExceptions(String message) {
        super(message);
    }

    public CustomExceptions(String message, Throwable cause) {
        super(message, cause);
    }
}
