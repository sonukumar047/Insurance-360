package com.example.policy360.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyStatisticsDto {
    private long totalPolicies;
    private long activePolicies;
    private long expiredPolicies;
    private long suspendedPolicies;
    private long cancelledPolicies;

    private Map<String, Long> policyCountByStatus;
    private Map<String, Long> policyCountByType;
    private Map<String, BigDecimal> revenueByType;

    private BigDecimal totalRevenue;
    private BigDecimal averagePremium;
    private BigDecimal averageCoverage;

    private int policiesCreatedThisMonth;
    private int policiesExpiredThisMonth;
    private int policiesRenewedThisMonth;
}
