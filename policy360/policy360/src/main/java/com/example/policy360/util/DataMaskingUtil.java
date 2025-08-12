package com.example.policy360.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
@Slf4j
public class DataMaskingUtil {

    // Patterns for different data types
    private static final Pattern EMAIL_PATTERN = Pattern.compile("([a-zA-Z0-9])([a-zA-Z0-9._%+-]*)(@.*)");
    private static final Pattern PHONE_PATTERN = Pattern.compile("(\\d{3})(\\d*)(\\d{3})");
    private static final Pattern POLICY_NUMBER_PATTERN = Pattern.compile("([A-Z]{3}-)(.*)(-\\d{3})");
    private static final Pattern CLAIM_NUMBER_PATTERN = Pattern.compile("([A-Z]{3}-)(.*)(-\\d{3})");

    /**
     * Mask email addresses
     * Example: john.doe@example.com -> j****@example.com
     */
    public String maskEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return email;
        }

        try {
            String[] parts = email.split("@");
            if (parts.length != 2) {
                return email;
            }

            String localPart = parts[0];
            String domainPart = parts[1];

            if (localPart.length() <= 1) {
                return email;
            }

            String maskedLocal = localPart.charAt(0) + "*".repeat(Math.max(1, localPart.length() - 1));
            return maskedLocal + "@" + domainPart;
        } catch (Exception e) {
            log.warn("Error masking email: {}", e.getMessage());
            return email;
        }
    }

    /**
     * Mask phone numbers
     * Example: 1234567890 -> 123****890
     */
    public String maskPhoneNumber(String phone) {
        if (phone == null || phone.trim().isEmpty()) {
            return phone;
        }

        String cleanPhone = phone.replaceAll("[^0-9]", "");

        if (cleanPhone.length() < 6) {
            return phone;
        }

        if (cleanPhone.length() == 10) {
            return cleanPhone.substring(0, 3) + "****" + cleanPhone.substring(7);
        } else if (cleanPhone.length() > 10) {
            int start = cleanPhone.length() - 7;
            int end = cleanPhone.length() - 3;
            return cleanPhone.substring(0, 3) + "*".repeat(end - 3) + cleanPhone.substring(end);
        }

        return phone;
    }

    /**
     * Mask full names
     * Example: John Doe Smith -> J*** D** S****
     */
    public String maskFullName(String fullName) {
        if (fullName == null || fullName.trim().isEmpty()) {
            return fullName;
        }

        String[] nameParts = fullName.trim().split("\\s+");
        StringBuilder maskedName = new StringBuilder();

        for (int i = 0; i < nameParts.length; i++) {
            String part = nameParts[i];
            if (part.length() > 0) {
                if (i > 0) maskedName.append(" ");
                maskedName.append(part.charAt(0));
                if (part.length() > 1) {
                    maskedName.append("*".repeat(part.length() - 1));
                }
            }
        }

        return maskedName.toString();
    }

    /**
     * Mask policy numbers
     * Example: POL-2024-001 -> POL-****-001
     */
    public String maskPolicyNumber(String policyNumber) {
        if (policyNumber == null || policyNumber.trim().isEmpty()) {
            return policyNumber;
        }

        String[] parts = policyNumber.split("-");
        if (parts.length >= 3) {
            return parts[0] + "-****-" + parts[parts.length - 1];
        }

        return policyNumber;
    }

    /**
     * Mask claim numbers
     * Example: CLM-2024-001 -> CLM-****-001
     */
    public String maskClaimNumber(String claimNumber) {
        if (claimNumber == null || claimNumber.trim().isEmpty()) {
            return claimNumber;
        }

        String[] parts = claimNumber.split("-");
        if (parts.length >= 3) {
            return parts[0] + "-****-" + parts[parts.length - 1];
        }

        return claimNumber;
    }

    /**
     * Mask financial amounts (keep only currency and last 2 digits)
     * Example: 1234.56 -> ****.56
     */
    public String maskAmount(Double amount) {
        if (amount == null) {
            return null;
        }

        String amountStr = String.format("%.2f", amount);
        String[] parts = amountStr.split("\\.");

        if (parts.length == 2) {
            return "*".repeat(parts[0].length()) + "." + parts[1];
        }

        return "*".repeat(amountStr.length() - 2) + amountStr.substring(amountStr.length() - 2);
    }

    /**
     * Partial masking for addresses
     * Example: 123 Main Street, City -> 1** M*** Street, C***
     */
    public String maskAddress(String address) {
        if (address == null || address.trim().isEmpty()) {
            return address;
        }

        String[] words = address.split("\\s+");
        StringBuilder maskedAddress = new StringBuilder();

        for (int i = 0; i < words.length; i++) {
            String word = words[i];
            if (i > 0) maskedAddress.append(" ");

            if (word.length() <= 2) {
                maskedAddress.append(word);
            } else {
                maskedAddress.append(word.charAt(0));
                maskedAddress.append("*".repeat(word.length() - 1));
            }
        }

        return maskedAddress.toString();
    }

    /**
     * General purpose masking for sensitive strings
     */
    public String maskSensitiveData(String data, int visibleChars) {
        if (data == null || data.trim().isEmpty()) {
            return data;
        }

        if (data.length() <= visibleChars) {
            return data;
        }

        return data.substring(0, visibleChars) + "*".repeat(data.length() - visibleChars);
    }

    /**
     * Check if user has permission to view unmasked data
     */
    public boolean canViewUnmaskedData(String userRole, String dataType) {
        return switch (userRole) {
            case "ADMIN" -> true; // Admin can see everything
            case "AGENT" -> !"FINANCIAL".equals(dataType); // Agent can't see financial details
            case "CUSTOMER" -> false; // Customer sees only masked data of others
            default -> false;
        };
    }
}
