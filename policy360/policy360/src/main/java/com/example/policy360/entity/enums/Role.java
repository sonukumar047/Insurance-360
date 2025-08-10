package com.example.policy360.entity.enums;

public enum Role {
    ADMIN("Administrator with full system access"),
    AGENT("Insurance agent with limited access"),
    CUSTOMER("Customer with policy and claim access");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
