// src/main/java/com/example/policy360/service/PolicyService.java
package com.example.policy360.service;

import com.example.policy360.dto.PolicyDto;
import com.example.policy360.dto.PolicyStatisticsDto;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.PolicyType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

public interface PolicyService {
    // Basic CRUD operations
    PolicyDto createPolicy(PolicyDto policyDto);
    PolicyDto getPolicyById(Long id);
    PolicyDto getPolicyByNumber(String policyNumber);
    Page<PolicyDto> getAllPolicies(Pageable pageable);
    List<PolicyDto> getAllPolicies();
    PolicyDto updatePolicy(Long id, PolicyDto policyDto);
    void deletePolicy(Long id);

    // Customer-related operations
    List<PolicyDto> getPoliciesByCustomerId(Long customerId);
    Page<PolicyDto> getPoliciesByCustomerId(Long customerId, Pageable pageable);
    BigDecimal getTotalPremiumByCustomer(Long customerId);
    boolean isCustomerOwnedByUser(Long customerId, String username);

    // Search and filtering
    Page<PolicyDto> searchPolicies(String policyNumber, String policyType, String status, Long customerId, Pageable pageable);
    List<PolicyDto> getPoliciesByType(PolicyType policyType);
    List<PolicyDto> getPoliciesByStatus(PolicyStatus status);
    Page<PolicyDto> getPoliciesByStatus(PolicyStatus status, Pageable pageable);

    // Business operations
    PolicyDto updatePolicyStatus(Long id, String status);
    PolicyDto renewPolicy(Long id);
    PolicyDto renewPolicy(Long id, PolicyDto updates);
    void cancelPolicy(Long id, String reason);
    void suspendPolicy(Long id, String reason);
    void reactivatePolicy(Long id);

    // Expiration and renewal management
    List<PolicyDto> getExpiringPolicies(int days);
    List<PolicyDto> getPoliciesEligibleForRenewal();
    List<PolicyDto> getPoliciesNearRenewal(int days);
    void sendExpirationReminders();
    void sendRenewalReminders();

    // Premium and coverage operations
    BigDecimal calculateRenewalPremium(Long policyId, PolicyDto updates);
    PolicyDto adjustPremium(Long id, BigDecimal newPremiumAmount, String reason);
    PolicyDto adjustCoverage(Long id, BigDecimal newCoverageAmount, String reason);

    // Statistics and reporting
    PolicyStatisticsDto getPolicyStatistics();
    Map<String, Long> getPolicyCountByStatus();
    Map<String, Long> getPolicyCountByType();
    Map<String, BigDecimal> getRevenueBykeyType();
    List<PolicyDto> getTopPoliciesByPremium(int limit);

    // Validation and business rules
    boolean validatePolicy(PolicyDto policyDto);
    List<String> getAvailablePolicyTypes();
    List<String> getAvailablePolicyStatuses();
    boolean canCustomerHavePolicy(Long customerId, PolicyType policyType);

    // Bulk operations
    List<PolicyDto> createMultiplePolicies(List<PolicyDto> policies);
    void bulkUpdateStatus(List<Long> policyIds, PolicyStatus status);
    void bulkSendNotifications(List<Long> policyIds, String notificationType);

    // Integration with claims
    boolean hasPendingClaims(Long policyId);
    BigDecimal getTotalClaimsAmount(Long policyId);
    int getTotalClaimsCount(Long policyId);
}
