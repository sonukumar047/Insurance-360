package com.example.policy360.entity.enums;

public enum ClaimStatus {
    PENDING("Claim is pending review"),
    PROCESSING("Claim is being processed"),
    APPROVED("Claim has been approved"),
    REJECTED("Claim has been rejected"),
    CANCELLED("Claim has been cancelled"),
    PAID("Claim has been paid");

    private final String description;

    ClaimStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean isTerminal() {
        return this == APPROVED || this == REJECTED || this == CANCELLED || this == PAID;
    }

    public boolean canBeModified() {
        return this == PENDING || this == PROCESSING;
    }
}
