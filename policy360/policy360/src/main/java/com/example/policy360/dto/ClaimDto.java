package com.example.policy360.dto;

import com.example.policy360.util.DataMaskingUtil;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimDto {
    private Long id;

    private String claimNumber;

    @NotNull(message = "Policy ID is required")
    private Long policyId;

    private String policyNumber;
    private String customerName;
    private String customerEmail;
    private String customerUsername;  // Added for ownership determination

    @NotBlank(message = "Description is required")
    @Size(min = 10, max = 1000, message = "Description must be between 10 and 1000 characters")
    private String description;

    @NotNull(message = "Claim amount is required")
    @DecimalMin(value = "1.00", message = "Claim amount must be at least $1.00")
    @Digits(integer = 8, fraction = 2, message = "Invalid claim amount format")
    private BigDecimal claimAmount;

    @NotNull(message = "Incident date is required")
    @PastOrPresent(message = "Incident date cannot be in the future")
    private LocalDateTime incidentDate;

    private String status;
    private String statusDescription;
    private LocalDateTime submittedDate;
    private LocalDateTime processedDate;
    private String rejectionReason;
    private BigDecimal approvedAmount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;

    // Additional fields for display
    private boolean canBeModified;
    private boolean isWithinCoverageLimit;
    private long daysSinceSubmission;
    private boolean isUrgent;
    private String assignedAgent;
    private String claimType;

    /**
     * Apply role-based masking to sensitive claim data
     * @param maskingUtil The masking utility
     * @param viewerRole The role of the user viewing this data (ADMIN, AGENT, CUSTOMER)
     * @param isOwnClaim Whether this claim belongs to the viewing customer
     * @return A new ClaimDto with appropriate masking applied
     */
    public ClaimDto applyMasking(DataMaskingUtil maskingUtil, String viewerRole, boolean isOwnClaim) {
        ClaimDto masked = this.toBuilder().build();

        // Role-based masking logic
        switch (viewerRole) {
            case "ADMIN":
                // Admins see everything unmasked (configurable)
                return masked;

            case "AGENT":
                // Agents see customer PII masked but can see financial and operational details
                if (this.customerName != null) {
                    masked.setCustomerName(maskingUtil.maskFullName(this.customerName));
                }
                if (this.customerEmail != null) {
                    masked.setCustomerEmail(maskingUtil.maskEmail(this.customerEmail));
                }
                // Agents can see financial details, claim amounts, etc.
                // Only mask personal identifiers
                return masked;

            case "CUSTOMER":
                if (isOwnClaim) {
                    // Customer viewing own claim - minimal masking
                    // Show most details but mask some sensitive operational info
                    if (this.assignedAgent != null) {
                        masked.setAssignedAgent(maskingUtil.maskFullName(this.assignedAgent));
                    }
                    // Show own claim number but partially masked
                    if (this.claimNumber != null) {
                        masked.setClaimNumber(maskingUtil.maskClaimNumber(this.claimNumber));
                    }
                } else {
                    // Customer viewing others' claims - full masking
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
    private ClaimDto applyFullMasking(DataMaskingUtil maskingUtil, ClaimDto claim) {
        // Mask all PII
        if (claim.getCustomerName() != null) {
            claim.setCustomerName(maskingUtil.maskFullName(claim.getCustomerName()));
        }
        if (claim.getCustomerEmail() != null) {
            claim.setCustomerEmail(maskingUtil.maskEmail(claim.getCustomerEmail()));
        }
        if (claim.getAssignedAgent() != null) {
            claim.setAssignedAgent(maskingUtil.maskFullName(claim.getAssignedAgent()));
        }

        // Mask financial details
        if (claim.getClaimAmount() != null) {
            String maskedAmount = maskingUtil.maskAmount(claim.getClaimAmount().doubleValue());
            claim.setClaimAmount(new BigDecimal(maskedAmount.replace("*", "0")));
        }
        if (claim.getApprovedAmount() != null) {
            String maskedAmount = maskingUtil.maskAmount(claim.getApprovedAmount().doubleValue());
            claim.setApprovedAmount(new BigDecimal(maskedAmount.replace("*", "0")));
        }

        // Mask identifiers
        if (claim.getClaimNumber() != null) {
            claim.setClaimNumber(maskingUtil.maskClaimNumber(claim.getClaimNumber()));
        }
        if (claim.getPolicyNumber() != null) {
            claim.setPolicyNumber(maskingUtil.maskPolicyNumber(claim.getPolicyNumber()));
        }

        // Mask sensitive descriptions
        if (claim.getDescription() != null && claim.getDescription().length() > 50) {
            claim.setDescription(maskingUtil.maskSensitiveData(claim.getDescription(), 50) + "...");
        }
        if (claim.getRejectionReason() != null && claim.getRejectionReason().length() > 30) {
            claim.setRejectionReason(maskingUtil.maskSensitiveData(claim.getRejectionReason(), 30) + "...");
        }

        return claim;
    }

    /**
     * Create a builder copy for immutable masking operations
     */
    public ClaimDtoBuilder toBuilder() {
        return ClaimDto.builder()
                .id(this.id)
                .claimNumber(this.claimNumber)
                .policyId(this.policyId)
                .policyNumber(this.policyNumber)
                .customerName(this.customerName)
                .customerEmail(this.customerEmail)
                .customerUsername(this.customerUsername)
                .description(this.description)
                .claimAmount(this.claimAmount)
                .incidentDate(this.incidentDate)
                .status(this.status)
                .statusDescription(this.statusDescription)
                .submittedDate(this.submittedDate)
                .processedDate(this.processedDate)
                .rejectionReason(this.rejectionReason)
                .approvedAmount(this.approvedAmount)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .createdBy(this.createdBy)
                .updatedBy(this.updatedBy)
                .canBeModified(this.canBeModified)
                .isWithinCoverageLimit(this.isWithinCoverageLimit)
                .daysSinceSubmission(this.daysSinceSubmission)
                .isUrgent(this.isUrgent)
                .assignedAgent(this.assignedAgent)
                .claimType(this.claimType);
    }

    /**
     * Utility method to check if financial data should be masked for the viewer
     */
    public boolean shouldMaskFinancialData(String viewerRole, boolean isOwnClaim) {
        return switch (viewerRole) {
            case "ADMIN" -> false; // Admin sees all
            case "AGENT" -> false; // Agent sees financial data
            case "CUSTOMER" -> !isOwnClaim; // Customer only sees own financial data
            default -> true; // Unknown role - mask everything
        };
    }

    /**
     * Utility method to check if PII should be masked for the viewer
     */
    public boolean shouldMaskPII(String viewerRole, boolean isOwnClaim) {
        return switch (viewerRole) {
            case "ADMIN" -> false; // Admin sees all
            case "AGENT" -> true;  // Agent sees masked PII
            case "CUSTOMER" -> !isOwnClaim; // Customer only sees own PII
            default -> true; // Unknown role - mask everything
        };
    }

    /**
     * Get a summary of what data is masked for logging/audit purposes
     */
    public String getMaskingSummary(String viewerRole, boolean isOwnClaim) {
        StringBuilder summary = new StringBuilder();
        summary.append("Role: ").append(viewerRole);
        summary.append(", OwnClaim: ").append(isOwnClaim);
        summary.append(", MaskPII: ").append(shouldMaskPII(viewerRole, isOwnClaim));
        summary.append(", MaskFinancial: ").append(shouldMaskFinancialData(viewerRole, isOwnClaim));
        return summary.toString();
    }

    /**
     * Check if the claim is in a processable state
     */
    public boolean isProcessable() {
        return "SUBMITTED".equals(this.status) || "UNDER_REVIEW".equals(this.status);
    }

    /**
     * Check if the claim is finalized (approved or rejected)
     */
    public boolean isFinalized() {
        return "APPROVED".equals(this.status) || "REJECTED".equals(this.status) || "PAID".equals(this.status);
    }

    /**
     * Get display-friendly claim amount with masking consideration
     */
    public String getDisplayAmount(String viewerRole, boolean isOwnClaim) {
        if (shouldMaskFinancialData(viewerRole, isOwnClaim)) {
            return "****.**";
        }
        return this.claimAmount != null ? this.claimAmount.toString() : "0.00";
    }

    /**
     * Get display-friendly approved amount with masking consideration
     */
    public String getDisplayApprovedAmount(String viewerRole, boolean isOwnClaim) {
        if (shouldMaskFinancialData(viewerRole, isOwnClaim)) {
            return "****.**";
        }
        return this.approvedAmount != null ? this.approvedAmount.toString() : "N/A";
    }

    /**
     * Validate if claim data is consistent
     */
    public boolean isDataConsistent() {
        // Basic consistency checks
        if (this.claimAmount != null && this.approvedAmount != null) {
            return this.approvedAmount.compareTo(this.claimAmount) <= 0;
        }

        if (this.submittedDate != null && this.processedDate != null) {
            return !this.processedDate.isBefore(this.submittedDate);
        }

        return true;
    }
}
