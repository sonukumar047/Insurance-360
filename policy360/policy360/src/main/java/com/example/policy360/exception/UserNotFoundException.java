package com.example.policy360.exception;

public class UserNotFoundException extends CustomExceptions {

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
