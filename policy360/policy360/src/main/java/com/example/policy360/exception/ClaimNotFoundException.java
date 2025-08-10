package com.example.policy360.exception;

public class ClaimNotFoundException extends CustomExceptions {

    public ClaimNotFoundException(String message) {
        super(message);
    }

    public ClaimNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
