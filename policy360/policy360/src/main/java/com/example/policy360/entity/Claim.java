package com.example.policy360.entity;

import com.example.policy360.entity.enums.ClaimStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "claims")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Claim {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "claim_number", unique = true, nullable = false)
    private String claimNumber;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Column(name = "description", nullable = false, columnDefinition = "TEXT")
    private String description;

    @Column(name = "claim_amount", nullable = false, precision = 10, scale = 2)
    private BigDecimal claimAmount;

    @Column(name = "incident_date", nullable = false)
    private LocalDateTime incidentDate;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private ClaimStatus status = ClaimStatus.PENDING;

    @Column(name = "submitted_date")
    private LocalDateTime submittedDate;

    @Column(name = "processed_date")
    private LocalDateTime processedDate;

    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;

    @Column(name = "approved_amount", precision = 10, scale = 2)
    private BigDecimal approvedAmount;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at")
    private LocalDateTime updatedAt = LocalDateTime.now();

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
        if (submittedDate == null) {
            submittedDate = now;
        }
        if (status == null) {
            status = ClaimStatus.PENDING;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
        if (status == ClaimStatus.APPROVED || status == ClaimStatus.REJECTED) {
            processedDate = updatedAt;
        }
    }

    // Business methods
    public boolean canBeProcessed() {
        return status == ClaimStatus.PENDING || status == ClaimStatus.PROCESSING;
    }

    public boolean isWithinCoverageLimit() {
        return claimAmount.compareTo(policy.getCoverageAmount()) <= 0;
    }

    public long getDaysSinceSubmission() {
        return submittedDate.toLocalDate().until(LocalDateTime.now().toLocalDate()).getDays();
    }
}
