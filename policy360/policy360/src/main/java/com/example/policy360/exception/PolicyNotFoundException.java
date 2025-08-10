package com.example.policy360.exception;

public class PolicyNotFoundException extends CustomExceptions {

    public PolicyNotFoundException(String message) {
        super(message);
    }

    public PolicyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}

