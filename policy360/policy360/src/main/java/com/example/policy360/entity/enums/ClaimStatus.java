package com.example.policy360.entity.enums;

public enum ClaimStatus {
    PENDING("Claim is pending review"),
    PROCESSING("Claim is being processed"),
    APPROVED("Claim has been approved"),
    REJECTED("Claim has been rejected");

    private final String description;

    ClaimStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }
}
