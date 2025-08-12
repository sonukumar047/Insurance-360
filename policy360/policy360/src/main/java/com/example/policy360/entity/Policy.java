package com.example.policy360.entity;

import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.PolicyType;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Entity
@Table(name = "policies", indexes = {
        @Index(name = "idx_policy_number", columnList = "policy_number"),
        @Index(name = "idx_customer_id", columnList = "customer_id"),
        @Index(name = "idx_policy_type", columnList = "policy_type"),
        @Index(name = "idx_status", columnList = "status"),
        @Index(name = "idx_end_date", columnList = "end_date")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Policy {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "policy_number", unique = true, nullable = false, length = 50)
    @Size(min = 5, max = 50, message = "Policy number must be between 5 and 50 characters")
    private String policyNumber;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "customer_id", nullable = false)
    @NotNull(message = "Customer is required")
    private User customer;

    @Enumerated(EnumType.STRING)
    @Column(name = "policy_type", nullable = false, length = 30)
    @NotNull(message = "Policy type is required")
    private PolicyType policyType;

    @Column(name = "premium_amount", nullable = false, precision = 10, scale = 2)
    @DecimalMin(value = "100.00", message = "Premium amount must be at least $100.00")
    @Digits(integer = 8, fraction = 2, message = "Premium amount format is invalid")
    private BigDecimal premiumAmount;

    @Column(name = "coverage_amount", nullable = false, precision = 15, scale = 2)
    @DecimalMin(value = "1000.00", message = "Coverage amount must be at least $1000.00")
    @Digits(integer = 13, fraction = 2, message = "Coverage amount format is invalid")
    private BigDecimal coverageAmount;

    @Column(name = "start_date", nullable = false)
    @NotNull(message = "Start date is required")
    private LocalDate startDate;

    @Column(name = "end_date", nullable = false)
    @NotNull(message = "End date is required")
    private LocalDate endDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    @NotNull(message = "Status is required")
    private PolicyStatus status;

    @Column(name = "deductible_amount", precision = 10, scale = 2)
    private BigDecimal deductibleAmount = BigDecimal.ZERO;

    @Column(name = "renewal_date")
    private LocalDate renewalDate;

    @Column(name = "policy_terms", columnDefinition = "TEXT")
    private String policyTerms;

    @Column(name = "beneficiary_name", length = 100)
    private String beneficiaryName;

    @Column(name = "beneficiary_relationship", length = 50)
    private String beneficiaryRelationship;

    @Column(name = "agent_commission_rate", precision = 5, scale = 2)
    private BigDecimal agentCommissionRate = BigDecimal.valueOf(5.00); // Default 5%

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "created_by", length = 50)
    private String createdBy;

    @Column(name = "updated_by", length = 50)
    private String updatedBy;

    // Relationship with claims
    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Claim> claims;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (status == null) {
            status = PolicyStatus.ACTIVE;
        }
        if (renewalDate == null && endDate != null) {
            renewalDate = endDate.minusMonths(1); // Default renewal reminder 1 month before expiry
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Business logic methods
    public boolean isExpired() {
        return endDate.isBefore(LocalDate.now()) || status == PolicyStatus.EXPIRED;
    }

    public boolean canBeClaimed() {
        return status == PolicyStatus.ACTIVE && !isExpired();
    }

    public long getDaysUntilExpiry() {
        if (isExpired()) {
            return 0;
        }
        return ChronoUnit.DAYS.between(LocalDate.now(), endDate);
    }

    public boolean isNearExpiry(int days) {
        return getDaysUntilExpiry() <= days && getDaysUntilExpiry() > 0;
    }

    public BigDecimal calculateAnnualPremium() {
        return premiumAmount.multiply(BigDecimal.valueOf(12));
    }

    public BigDecimal calculateCommissionAmount() {
        return premiumAmount.multiply(agentCommissionRate).divide(BigDecimal.valueOf(100));
    }

    public boolean isEligibleForRenewal() {
        return status == PolicyStatus.ACTIVE && getDaysUntilExpiry() <= 60;
    }

    public double getCoverageRatio() {
        return coverageAmount.divide(premiumAmount, 2, BigDecimal.ROUND_HALF_UP).doubleValue();
    }

    public long getPolicyDurationInMonths() {
        return ChronoUnit.MONTHS.between(startDate, endDate);
    }
}
