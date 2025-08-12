package com.example.policy360.entity.enums;

public enum PolicyType {
    HEALTH_INSURANCE("Health Insurance Coverage"),
    LIFE_INSURANCE("Life Insurance Coverage"),
    AUTO_INSURANCE("Automobile Insurance Coverage"),
    HOME_INSURANCE("Home Insurance Coverage"),
    TRAVEL_INSURANCE("Travel Insurance Coverage"),
    COMPREHENSIVE_HEALTH("Comprehensive Health Insurance Coverage");

    private final String description;

    PolicyType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public String getDisplayName() {
        return description;
    }
}
