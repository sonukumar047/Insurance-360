package com.example.policy360.entity.enums;

public enum PolicyStatus {
    ACTIVE("Policy is currently active"),
    EXPIRED("Policy has expired"),
    CANCELLED("Policy has been cancelled"),
    SUSPENDED("Policy is temporarily suspended");

    private final String description;

    PolicyStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
