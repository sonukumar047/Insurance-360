package com.example.policy360.dto;

import com.example.policy360.util.DataMaskingUtil;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyDto {
    private Long id;

    @NotBlank(message = "Policy number is required")
    @Size(min = 5, max = 50, message = "Policy number must be between 5 and 50 characters")
    private String policyNumber;

    @NotNull(message = "Customer ID is required")
    @Positive(message = "Customer ID must be positive")
    private Long customerId;

    private String customerName;
    private String customerEmail;
    private String customerUsername; // ✅ ADDED: Critical for ownership determination

    @NotBlank(message = "Policy type is required")
    private String policyType;

    private String policyTypeDescription;

    @NotNull(message = "Premium amount is required")
    @DecimalMin(value = "100.00", message = "Premium amount must be at least $100.00")
    @Digits(integer = 8, fraction = 2, message = "Premium amount format is invalid")
    private BigDecimal premiumAmount;

    @NotNull(message = "Coverage amount is required")
    @DecimalMin(value = "1000.00", message = "Coverage amount must be at least $1000.00")
    @Digits(integer = 13, fraction = 2, message = "Coverage amount format is invalid")
    private BigDecimal coverageAmount;

    @NotNull(message = "Start date is required")
    @FutureOrPresent(message = "Start date cannot be in the past")
    private LocalDate startDate;

    @NotNull(message = "End date is required")
    @Future(message = "End date must be in the future")
    private LocalDate endDate;

    private String status;
    private String statusDescription;

    @DecimalMin(value = "0.00", message = "Deductible amount cannot be negative")
    private BigDecimal deductibleAmount;

    private LocalDate renewalDate;

    @Size(max = 1000, message = "Policy terms cannot exceed 1000 characters")
    private String policyTerms;

    @Size(max = 100, message = "Beneficiary name cannot exceed 100 characters")
    private String beneficiaryName;

    @Size(max = 50, message = "Beneficiary relationship cannot exceed 50 characters")
    private String beneficiaryRelationship;

    @DecimalMin(value = "0.00", message = "Commission rate cannot be negative")
    @DecimalMax(value = "50.00", message = "Commission rate cannot exceed 50%")
    private BigDecimal agentCommissionRate;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;

    // Calculated fields
    private boolean isExpired;
    private boolean canBeClaimed;
    private long daysUntilExpiry;
    private boolean isNearExpiry;
    private boolean isEligibleForRenewal;
    private BigDecimal annualPremium;
    private BigDecimal commissionAmount;
    private double coverageRatio;
    private long policyDurationInMonths;
    private int totalClaims;
    private BigDecimal totalClaimsAmount;

    /**
     * Apply role-based masking to sensitive policy data
     * @param maskingUtil The masking utility
     * @param viewerRole The role of the user viewing this data (ADMIN, AGENT, CUSTOMER)
     * @param isOwnPolicy Whether this policy belongs to the viewing customer
     * @return A new PolicyDto with appropriate masking applied
     */
    public PolicyDto applyMasking(DataMaskingUtil maskingUtil, String viewerRole, boolean isOwnPolicy) {
        PolicyDto masked = this.toBuilder().build();

        // Role-based masking logic
        switch (viewerRole) {
            case "ADMIN":
                // Admins see everything unmasked (configurable)
                return masked;

            case "AGENT":
                // Agents see customer PII masked but can see financial details
                if (this.customerName != null) {
                    masked.setCustomerName(maskingUtil.maskFullName(this.customerName));
                }
                if (this.customerEmail != null) {
                    masked.setCustomerEmail(maskingUtil.maskEmail(this.customerEmail));
                }
                if (this.beneficiaryName != null) {
                    masked.setBeneficiaryName(maskingUtil.maskFullName(this.beneficiaryName));
                }
                // Agents can see financial details, so don't mask amounts
                return masked;

            case "CUSTOMER":
                if (isOwnPolicy) {
                    // Customer viewing own policy - minimal masking
                    if (this.beneficiaryName != null) {
                        masked.setBeneficiaryName(maskingUtil.maskFullName(this.beneficiaryName));
                    }
                    // Show own financial details but mask policy number partially
                    if (this.policyNumber != null) {
                        masked.setPolicyNumber(maskingUtil.maskPolicyNumber(this.policyNumber));
                    }
                } else {
                    // Customer viewing others' policies - full masking
                    masked = applyFullMasking(maskingUtil, masked);
                }
                return masked;

            default:
                // Unknown role - apply full masking
                return applyFullMasking(maskingUtil, masked);
        }
    }

    /**
     * Apply comprehensive masking for maximum privacy
     */
    private PolicyDto applyFullMasking(DataMaskingUtil maskingUtil, PolicyDto policy) {
        // Mask all PII
        if (policy.getCustomerName() != null) {
            policy.setCustomerName(maskingUtil.maskFullName(policy.getCustomerName()));
        }
        if (policy.getCustomerEmail() != null) {
            policy.setCustomerEmail(maskingUtil.maskEmail(policy.getCustomerEmail()));
        }
        if (policy.getBeneficiaryName() != null) {
            policy.setBeneficiaryName(maskingUtil.maskFullName(policy.getBeneficiaryName()));
        }

        // ✅ FIXED: Proper financial data masking with safer BigDecimal handling
        if (policy.getPremiumAmount() != null) {
            policy.setPremiumAmount(maskFinancialAmount(maskingUtil, policy.getPremiumAmount()));
        }
        if (policy.getCoverageAmount() != null) {
            policy.setCoverageAmount(maskFinancialAmount(maskingUtil, policy.getCoverageAmount()));
        }
        if (policy.getDeductibleAmount() != null) {
            policy.setDeductibleAmount(maskFinancialAmount(maskingUtil, policy.getDeductibleAmount()));
        }
        if (policy.getAnnualPremium() != null) {
            policy.setAnnualPremium(maskFinancialAmount(maskingUtil, policy.getAnnualPremium()));
        }
        if (policy.getCommissionAmount() != null) {
            policy.setCommissionAmount(maskFinancialAmount(maskingUtil, policy.getCommissionAmount()));
        }
        if (policy.getTotalClaimsAmount() != null) {
            policy.setTotalClaimsAmount(maskFinancialAmount(maskingUtil, policy.getTotalClaimsAmount()));
        }

        // Mask policy identifiers
        if (policy.getPolicyNumber() != null) {
            policy.setPolicyNumber(maskingUtil.maskPolicyNumber(policy.getPolicyNumber()));
        }

        // Mask sensitive terms
        if (policy.getPolicyTerms() != null && policy.getPolicyTerms().length() > 50) {
            policy.setPolicyTerms(maskingUtil.maskSensitiveData(policy.getPolicyTerms(), 50) + "...");
        }

        return policy;
    }

    /**
     * ✅ ADDED: Helper method for safe financial amount masking
     */
    private BigDecimal maskFinancialAmount(DataMaskingUtil maskingUtil, BigDecimal amount) {
        try {
            String maskedAmount = maskingUtil.maskAmount(amount.doubleValue());
            // Convert masked string back to valid BigDecimal
            String numericValue = maskedAmount.replaceAll("\\*", "0");
            return new BigDecimal(numericValue);
        } catch (Exception e) {
            // Fallback to zero if masking fails
            return BigDecimal.ZERO;
        }
    }

    /**
     * ✅ CORRECTED: Create a builder copy for immutable masking operations
     */
    public PolicyDtoBuilder toBuilder() {
        return PolicyDto.builder()
                .id(this.id)
                .policyNumber(this.policyNumber)
                .customerId(this.customerId)
                .customerName(this.customerName)
                .customerEmail(this.customerEmail)
                .customerUsername(this.customerUsername) // ✅ ADDED: Include customerUsername
                .policyType(this.policyType)
                .policyTypeDescription(this.policyTypeDescription)
                .premiumAmount(this.premiumAmount)
                .coverageAmount(this.coverageAmount)
                .startDate(this.startDate)
                .endDate(this.endDate)
                .status(this.status)
                .statusDescription(this.statusDescription)
                .deductibleAmount(this.deductibleAmount)
                .renewalDate(this.renewalDate)
                .policyTerms(this.policyTerms)
                .beneficiaryName(this.beneficiaryName)
                .beneficiaryRelationship(this.beneficiaryRelationship)
                .agentCommissionRate(this.agentCommissionRate)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .createdBy(this.createdBy)
                .updatedBy(this.updatedBy)
                .isExpired(this.isExpired)
                .canBeClaimed(this.canBeClaimed)
                .daysUntilExpiry(this.daysUntilExpiry)
                .isNearExpiry(this.isNearExpiry)
                .isEligibleForRenewal(this.isEligibleForRenewal)
                .annualPremium(this.annualPremium)
                .commissionAmount(this.commissionAmount)
                .coverageRatio(this.coverageRatio)
                .policyDurationInMonths(this.policyDurationInMonths)
                .totalClaims(this.totalClaims)
                .totalClaimsAmount(this.totalClaimsAmount);
    }

    /**
     * Utility method to check if financial data should be masked for the viewer
     */
    public boolean shouldMaskFinancialData(String viewerRole, boolean isOwnPolicy) {
        return switch (viewerRole) {
            case "ADMIN" -> false; // Admin sees all
            case "AGENT" -> false; // Agent sees financial data
            case "CUSTOMER" -> !isOwnPolicy; // Customer only sees own financial data
            default -> true; // Unknown role - mask everything
        };
    }

    /**
     * Utility method to check if PII should be masked for the viewer
     */
    public boolean shouldMaskPII(String viewerRole, boolean isOwnPolicy) {
        return switch (viewerRole) {
            case "ADMIN" -> false; // Admin sees all
            case "AGENT" -> true;  // Agent sees masked PII
            case "CUSTOMER" -> !isOwnPolicy; // Customer only sees own PII
            default -> true; // Unknown role - mask everything
        };
    }

    /**
     * Get a summary of what data is masked for logging/audit purposes
     */
    public String getMaskingSummary(String viewerRole, boolean isOwnPolicy) {
        StringBuilder summary = new StringBuilder();
        summary.append("Role: ").append(viewerRole);
        summary.append(", OwnPolicy: ").append(isOwnPolicy);
        summary.append(", MaskPII: ").append(shouldMaskPII(viewerRole, isOwnPolicy));
        summary.append(", MaskFinancial: ").append(shouldMaskFinancialData(viewerRole, isOwnPolicy));
        return summary.toString();
    }

    /**
     * ✅ ADDED: Check if the policy is in a processable state
     */
    public boolean isProcessable() {
        return "ACTIVE".equals(this.status) || "PENDING".equals(this.status);
    }

    /**
     * ✅ ADDED: Check if the policy is finalized
     */
    public boolean isFinalized() {
        return "EXPIRED".equals(this.status) || "CANCELLED".equals(this.status) || "TERMINATED".equals(this.status);
    }

    /**
     * ✅ ADDED: Get display-friendly premium amount with masking consideration
     */
    public String getDisplayPremiumAmount(String viewerRole, boolean isOwnPolicy) {
        if (shouldMaskFinancialData(viewerRole, isOwnPolicy)) {
            return "****.**";
        }
        return this.premiumAmount != null ? this.premiumAmount.toString() : "0.00";
    }

    /**
     * ✅ ADDED: Get display-friendly coverage amount with masking consideration
     */
    public String getDisplayCoverageAmount(String viewerRole, boolean isOwnPolicy) {
        if (shouldMaskFinancialData(viewerRole, isOwnPolicy)) {
            return "****.**";
        }
        return this.coverageAmount != null ? this.coverageAmount.toString() : "0.00";
    }

    /**
     * ✅ ADDED: Validate if policy data is consistent
     */
    public boolean isDataConsistent() {
        // Basic consistency checks
        if (this.startDate != null && this.endDate != null) {
            if (!this.endDate.isAfter(this.startDate)) {
                return false;
            }
        }

        if (this.premiumAmount != null && this.coverageAmount != null) {
            if (this.premiumAmount.compareTo(this.coverageAmount) > 0) {
                return false; // Premium shouldn't exceed coverage
            }
        }

        if (this.createdAt != null && this.updatedAt != null) {
            return !this.updatedAt.isBefore(this.createdAt);
        }

        return true;
    }

    /**
     * ✅ ADDED: Get policy age in days
     */
    public long getPolicyAgeInDays() {
        if (this.createdAt == null) {
            return 0;
        }
        return java.time.Duration.between(this.createdAt, LocalDateTime.now()).toDays();
    }

    /**
     * ✅ ADDED: Check if policy needs attention (near expiry, high claims, etc.)
     */
    public boolean needsAttention() {
        return this.isNearExpiry ||
                (this.totalClaimsAmount != null && this.coverageAmount != null &&
                        this.totalClaimsAmount.compareTo(this.coverageAmount.multiply(new BigDecimal("0.8"))) > 0) ||
                this.isExpired;
    }
}
