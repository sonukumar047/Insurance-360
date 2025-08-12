package com.example.policy360.entity.enums;

public enum PolicyStatus {
    ACTIVE("Policy is currently active"),
    EXPIRED("Policy has expired"),
    CANCELLED("Policy has been cancelled"),
    SUSPENDED("Policy is temporarily suspended"),
    PENDING("Policy is pending approval"),
    TERMINATED("Policy has been terminated"),
    INACTIVE("Policy is inactive");

    private final String description;

    PolicyStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public String getDisplayName() {
        return description;
    }

    // Utility methods
    public boolean isActive() {
        return this == ACTIVE;
    }

    public boolean canBeModified() {
        return this == ACTIVE || this == SUSPENDED || this == PENDING;
    }

    public boolean isTerminal() {
        return this == EXPIRED || this == CANCELLED || this == TERMINATED;
    }
}
