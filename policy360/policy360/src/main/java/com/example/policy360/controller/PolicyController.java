package com.example.policy360.controller;

import com.example.policy360.dto.PolicyDto;
import com.example.policy360.dto.PolicyStatisticsDto;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.PolicyType;
import com.example.policy360.service.Impl.MaskingService;
import com.example.policy360.service.PolicyService;
import com.example.policy360.util.DataMaskingUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/policy")
@RequiredArgsConstructor
@Slf4j
public class PolicyController {

    private final PolicyService policyService;
    private final MaskingService maskingService;
    private final DataMaskingUtil dataMaskingUtil;

    // BASIC CRUD OPERATIONS

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<PolicyDto> getPolicyById(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policy with ID: {} (unmask: {})",
                currentUser, viewerRole, id, unmask);

        PolicyDto policy = policyService.getPolicyById(id);

        // Apply masking based on role and ownership
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnPolicy = isViewerOwnPolicy(policy, currentUser, viewerRole);
            policy = maskingService.maskPolicyData(policy, viewerRole, isOwnPolicy);
            log.info("Policy {} retrieved with masking applied (own: {})", id, isOwnPolicy);
        } else {
            log.info("Policy {} retrieved unmasked (admin privilege)", id);
        }

        return ResponseEntity.ok(policy);
    }

    @GetMapping("/number/{policyNumber}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<PolicyDto> getPolicyByNumber(
            @PathVariable String policyNumber,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policy with number: {} (unmask: {})",
                currentUser, viewerRole, policyNumber, unmask);

        PolicyDto policy = policyService.getPolicyByNumber(policyNumber);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnPolicy = isViewerOwnPolicy(policy, currentUser, viewerRole);
            policy = maskingService.maskPolicyData(policy, viewerRole, isOwnPolicy);
        }

        return ResponseEntity.ok(policy);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<PolicyDto>> getAllPolicies(
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching all policies with pagination: page={}, size={}, unmask={}",
                currentUser, viewerRole, pageable.getPageNumber(), pageable.getPageSize(), unmask);

        Page<PolicyDto> policies = policyService.getAllPolicies(pageable);

        // Apply masking to all policies
        if (!unmask || !canUnmaskData(viewerRole)) {
            policies = maskingService.maskPolicyDataPage(policies, viewerRole);
            log.info("Retrieved {} policies with masking applied", policies.getTotalElements());
        } else {
            log.info("Retrieved {} policies unmasked (admin privilege)", policies.getTotalElements());
        }

        return ResponseEntity.ok(policies);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<PolicyDto> createPolicy(@Valid @RequestBody PolicyDto policyDto,
                                                  HttpServletRequest request) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) creating policy for customer: {}",
                currentUser, viewerRole, policyDto.getCustomerId());

        // Log masking status of incoming data for audit
        String maskingSummary = getPolicyMaskingSummary(policyDto);
        log.info("Policy creation request masking summary: {}", maskingSummary);

        PolicyDto createdPolicy = policyService.createPolicy(policyDto);

        // Apply masking to response
        boolean isOwnPolicy = isViewerOwnPolicy(createdPolicy, currentUser, viewerRole);
        PolicyDto maskedResponse = maskingService.maskPolicyData(createdPolicy, viewerRole, isOwnPolicy);

        log.info("Policy created successfully with ID: {} and number: {} (masking: {})",
                createdPolicy.getId(), createdPolicy.getPolicyNumber(), !isOwnPolicy);
        return new ResponseEntity<>(maskedResponse, HttpStatus.CREATED);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<PolicyDto> updatePolicy(@PathVariable Long id,
                                                  @Valid @RequestBody PolicyDto policyDto,
                                                  HttpServletRequest request,
                                                  @RequestParam(defaultValue = "false") boolean unmask) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) updating policy with ID: {} (unmask: {})",
                currentUser, viewerRole, id, unmask);

        PolicyDto updatedPolicy = policyService.updatePolicy(id, policyDto);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnPolicy = isViewerOwnPolicy(updatedPolicy, currentUser, viewerRole);
            updatedPolicy = maskingService.maskPolicyData(updatedPolicy, viewerRole, isOwnPolicy);
        }

        log.info("Policy updated successfully with ID: {}", updatedPolicy.getId());
        return ResponseEntity.ok(updatedPolicy);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deletePolicy(@PathVariable Long id, HttpServletRequest request) {
        String currentUser = getCurrentUsername();
        log.info("Admin {} deleting policy with ID: {}", currentUser, id);

        // Log masked policy info for audit before deletion
        PolicyDto policyForAudit = policyService.getPolicyById(id);
        PolicyDto maskedForAudit = maskingService.maskPolicyData(policyForAudit, "ADMIN", false);
        log.info("Deleting policy: {} (number: {})", id, maskedForAudit.getPolicyNumber());

        policyService.deletePolicy(id);

        log.info("Policy deleted successfully with ID: {}", id);
        return ResponseEntity.noContent().build();
    }

    // CUSTOMER-RELATED OPERATIONS

    @GetMapping("/customer/{customerId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or " +
            "(hasRole('CUSTOMER') and @policySecurityService.canAccessCustomerPolicies(authentication.name, #customerId))")
    public ResponseEntity<List<PolicyDto>> getPoliciesByCustomerId(
            @PathVariable Long customerId,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policies for customer ID: {} (unmask: {})",
                currentUser, viewerRole, customerId, unmask);

        List<PolicyDto> policies = policyService.getPoliciesByCustomerId(customerId);

        // Apply masking to list - customers see their own policies with less masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            policies = maskingService.maskPolicyDataList(policies, viewerRole, currentUser);
            log.info("Retrieved {} policies for customer {} with masking", policies.size(), customerId);
        } else {
            log.info("Retrieved {} policies for customer {} unmasked", policies.size(), customerId);
        }

        return ResponseEntity.ok(policies);
    }

    @GetMapping("/customer/{customerId}/paginated")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or " +
            "(hasRole('CUSTOMER') and @policySecurityService.canAccessCustomerPolicies(authentication.name, #customerId))")
    public ResponseEntity<Page<PolicyDto>> getPoliciesByCustomerIdPaginated(
            @PathVariable Long customerId,
            @PageableDefault(size = 10, sort = "createdAt") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching paginated policies for customer ID: {} (unmask: {})",
                currentUser, viewerRole, customerId, unmask);

        Page<PolicyDto> policies = policyService.getPoliciesByCustomerId(customerId, pageable);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            policies = maskingService.maskPolicyDataPage(policies, viewerRole, currentUser);
        }

        return ResponseEntity.ok(policies);
    }

    @GetMapping("/customer/{customerId}/premium-total")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or " +
            "(hasRole('CUSTOMER') and @policySecurityService.canAccessCustomerPolicies(authentication.name, #customerId))")
    public ResponseEntity<BigDecimal> getTotalPremiumByCustomer(
            @PathVariable Long customerId,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching total premium for customer ID: {} (unmask: {})",
                currentUser, viewerRole, customerId, unmask);

        BigDecimal totalPremium = policyService.getTotalPremiumByCustomer(customerId);

        // Apply financial masking if needed
        if (!unmask && shouldMaskFinancialData(viewerRole, customerId, currentUser)) {
            String maskedAmount = dataMaskingUtil.maskAmount(totalPremium.doubleValue());
            totalPremium = new BigDecimal(maskedAmount.replace("*", "0"));
            log.info("Total premium masked for security");
        }

        return ResponseEntity.ok(totalPremium);
    }

    // SEARCH AND FILTERING

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<PolicyDto>> searchPolicies(
            @RequestParam(required = false) String policyNumber,
            @RequestParam(required = false) String policyType,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Long customerId,
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) searching policies with filters - policyNumber: {}, policyType: {}, status: {}, customerId: {}, unmask: {}",
                currentUser, viewerRole, policyNumber, policyType, status, customerId, unmask);

        Page<PolicyDto> policies = policyService.searchPolicies(policyNumber, policyType, status, customerId, pageable);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            policies = maskingService.maskPolicyDataPage(policies, viewerRole);
            log.info("Search returned {} policies with masking applied", policies.getTotalElements());
        } else {
            log.info("Search returned {} policies unmasked", policies.getTotalElements());
        }

        return ResponseEntity.ok(policies);
    }

    @GetMapping("/type/{policyType}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<PolicyDto>> getPoliciesByType(
            @PathVariable String policyType,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policies with type: {} (unmask: {})",
                currentUser, viewerRole, policyType, unmask);

        try {
            PolicyType type = PolicyType.valueOf(policyType.toUpperCase());
            List<PolicyDto> policies = policyService.getPoliciesByType(type);

            // Apply masking
            if (!unmask || !canUnmaskData(viewerRole)) {
                policies = maskingService.maskPolicyDataList(policies, viewerRole, currentUser);
            }

            return ResponseEntity.ok(policies);
        } catch (IllegalArgumentException e) {
            log.error("Invalid policy type provided: {}", policyType);
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/status/{status}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<PolicyDto>> getPoliciesByStatus(
            @PathVariable String status,
            @PageableDefault(size = 20, sort = "createdAt") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policies with status: {} (unmask: {})",
                currentUser, viewerRole, status, unmask);

        try {
            PolicyStatus policyStatus = PolicyStatus.valueOf(status.toUpperCase());
            Page<PolicyDto> policies = policyService.getPoliciesByStatus(policyStatus, pageable);

            // Apply masking
            if (!unmask || !canUnmaskData(viewerRole)) {
                policies = maskingService.maskPolicyDataPage(policies, viewerRole);
            }

            return ResponseEntity.ok(policies);
        } catch (IllegalArgumentException e) {
            log.error("Invalid policy status provided: {}", status);
            return ResponseEntity.badRequest().build();
        }
    }

    // BUSINESS OPERATIONS

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<PolicyDto> updatePolicyStatus(
            @PathVariable Long id,
            @RequestParam String status,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) updating policy status for ID: {} to status: {}",
                currentUser, viewerRole, id, status);

        PolicyDto updatedPolicy = policyService.updatePolicyStatus(id, status);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnPolicy = isViewerOwnPolicy(updatedPolicy, currentUser, viewerRole);
            updatedPolicy = maskingService.maskPolicyData(updatedPolicy, viewerRole, isOwnPolicy);
        }

        log.info("Policy status updated successfully for ID: {}", id);
        return ResponseEntity.ok(updatedPolicy);
    }

    @PostMapping("/{id}/renew")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<PolicyDto> renewPolicy(
            @PathVariable Long id,
            @RequestBody(required = false) PolicyDto updates,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) renewing policy with ID: {}", currentUser, viewerRole, id);

        PolicyDto renewedPolicy = policyService.renewPolicy(id, updates);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnPolicy = isViewerOwnPolicy(renewedPolicy, currentUser, viewerRole);
            renewedPolicy = maskingService.maskPolicyData(renewedPolicy, viewerRole, isOwnPolicy);
        }

        log.info("Policy renewed successfully. New policy ID: {}", renewedPolicy.getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(renewedPolicy);
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Void> cancelPolicy(@PathVariable Long id,
                                             @RequestParam String reason) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) cancelling policy with ID: {} - Reason: {}",
                currentUser, viewerRole, id, reason);

        policyService.cancelPolicy(id, reason);

        log.info("Policy cancelled successfully with ID: {}", id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/suspend")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Void> suspendPolicy(@PathVariable Long id,
                                              @RequestParam String reason) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) suspending policy with ID: {} - Reason: {}",
                currentUser, viewerRole, id, reason);

        policyService.suspendPolicy(id, reason);

        log.info("Policy suspended successfully with ID: {}", id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/reactivate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Void> reactivatePolicy(@PathVariable Long id) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) reactivating policy with ID: {}", currentUser, viewerRole, id);

        policyService.reactivatePolicy(id);

        log.info("Policy reactivated successfully with ID: {}", id);
        return ResponseEntity.ok().build();
    }

    // EXPIRATION AND RENEWAL MANAGEMENT

    @GetMapping("/expiring")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<PolicyDto>> getExpiringPolicies(
            @RequestParam(defaultValue = "30") int days,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policies expiring within {} days (unmask: {})",
                currentUser, viewerRole, days, unmask);

        List<PolicyDto> expiringPolicies = policyService.getExpiringPolicies(days);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            expiringPolicies = maskingService.maskPolicyDataList(expiringPolicies, viewerRole, currentUser);
        }

        return ResponseEntity.ok(expiringPolicies);
    }

    @GetMapping("/eligible-for-renewal")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<PolicyDto>> getPoliciesEligibleForRenewal(
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policies eligible for renewal (unmask: {})",
                currentUser, viewerRole, unmask);

        List<PolicyDto> eligiblePolicies = policyService.getPoliciesEligibleForRenewal();

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            eligiblePolicies = maskingService.maskPolicyDataList(eligiblePolicies, viewerRole, currentUser);
        }

        return ResponseEntity.ok(eligiblePolicies);
    }

    @PostMapping("/send-expiration-reminders")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> sendExpirationReminders() {
        String currentUser = getCurrentUsername();
        log.info("Admin {} triggering expiration reminders", currentUser);

        policyService.sendExpirationReminders();

        return ResponseEntity.ok("Expiration reminders sent successfully");
    }

    @PostMapping("/send-renewal-reminders")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> sendRenewalReminders() {
        String currentUser = getCurrentUsername();
        log.info("Admin {} triggering renewal reminders", currentUser);

        policyService.sendRenewalReminders();

        return ResponseEntity.ok("Renewal reminders sent successfully");
    }

    // PREMIUM AND COVERAGE OPERATIONS

    @GetMapping("/{id}/renewal-premium")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<BigDecimal> calculateRenewalPremium(
            @PathVariable Long id,
            @RequestBody(required = false) PolicyDto updates,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) calculating renewal premium for policy ID: {} (unmask: {})",
                currentUser, viewerRole, id, unmask);

        BigDecimal renewalPremium = policyService.calculateRenewalPremium(id, updates);

        // Apply financial masking if needed
        if (!unmask && shouldMaskFinancialData(viewerRole)) {
            String maskedAmount = dataMaskingUtil.maskAmount(renewalPremium.doubleValue());
            renewalPremium = new BigDecimal(maskedAmount.replace("*", "0"));
        }

        return ResponseEntity.ok(renewalPremium);
    }

    @PatchMapping("/{id}/premium")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PolicyDto> adjustPremium(
            @PathVariable Long id,
            @RequestParam BigDecimal newAmount,
            @RequestParam String reason,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        log.info("Admin {} adjusting premium for policy ID: {} to amount: {}",
                currentUser, id, newAmount);

        PolicyDto updatedPolicy = policyService.adjustPremium(id, newAmount, reason);

        // Apply masking to response
        if (!unmask) {
            updatedPolicy = maskingService.maskPolicyData(updatedPolicy, "ADMIN", false);
        }

        log.info("Premium adjusted successfully for policy ID: {}", id);
        return ResponseEntity.ok(updatedPolicy);
    }

    @PatchMapping("/{id}/coverage")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PolicyDto> adjustCoverage(
            @PathVariable Long id,
            @RequestParam BigDecimal newAmount,
            @RequestParam String reason,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        log.info("Admin {} adjusting coverage for policy ID: {} to amount: {}",
                currentUser, id, newAmount);

        PolicyDto updatedPolicy = policyService.adjustCoverage(id, newAmount, reason);

        // Apply masking to response
        if (!unmask) {
            updatedPolicy = maskingService.maskPolicyData(updatedPolicy, "ADMIN", false);
        }

        log.info("Coverage adjusted successfully for policy ID: {}", id);
        return ResponseEntity.ok(updatedPolicy);
    }

    // STATISTICS AND REPORTING

    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<PolicyStatisticsDto> getPolicyStatistics() {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policy statistics", currentUser, viewerRole);

        PolicyStatisticsDto statistics = policyService.getPolicyStatistics();

        // Apply masking to statistics if needed (for agents)
        if (!"ADMIN".equals(viewerRole)) {
            statistics = maskingService.maskPolicyStatistics(statistics, viewerRole);
        }

        return ResponseEntity.ok(statistics);
    }

    @GetMapping("/count/by-status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Map<String, Long>> getPolicyCountByStatus() {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policy count by status", currentUser, viewerRole);

        Map<String, Long> statusCount = policyService.getPolicyCountByStatus();
        return ResponseEntity.ok(statusCount);
    }

    @GetMapping("/count/by-type")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Map<String, Long>> getPolicyCountByType() {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching policy count by type", currentUser, viewerRole);

        Map<String, Long> typeCount = policyService.getPolicyCountByType();
        return ResponseEntity.ok(typeCount);
    }

    @GetMapping("/revenue/by-type")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, BigDecimal>> getRevenueByType(
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        log.info("Admin {} fetching revenue by policy type (unmask: {})", currentUser, unmask);

        Map<String, BigDecimal> revenueByType = policyService.getRevenueBykeyType();

        // Apply financial masking if needed
        if (!unmask) {
            revenueByType = revenueByType.entrySet().stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            entry -> {
                                String masked = dataMaskingUtil.maskAmount(entry.getValue().doubleValue());
                                return new BigDecimal(masked.replace("*", "0"));
                            }
                    ));
        }

        return ResponseEntity.ok(revenueByType);
    }

    @GetMapping("/top-by-premium")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<PolicyDto>> getTopPoliciesByPremium(
            @RequestParam(defaultValue = "10") int limit,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching top {} policies by premium (unmask: {})",
                currentUser, viewerRole, limit, unmask);

        List<PolicyDto> topPolicies = policyService.getTopPoliciesByPremium(limit);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            topPolicies = maskingService.maskPolicyDataList(topPolicies, viewerRole, currentUser);
        }

        return ResponseEntity.ok(topPolicies);
    }

    // VALIDATION AND UTILITY ENDPOINTS

    @GetMapping("/types")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<List<String>> getAvailablePolicyTypes() {
        log.info("Fetching available policy types");

        List<String> policyTypes = policyService.getAvailablePolicyTypes();
        return ResponseEntity.ok(policyTypes);
    }

    @GetMapping("/statuses")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<List<String>> getAvailablePolicyStatuses() {
        log.info("Fetching available policy statuses");

        List<String> policyStatuses = policyService.getAvailablePolicyStatuses();
        return ResponseEntity.ok(policyStatuses);
    }

    @PostMapping("/validate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Boolean> validatePolicy(@Valid @RequestBody PolicyDto policyDto) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) validating policy", currentUser, viewerRole);

        boolean isValid = policyService.validatePolicy(policyDto);
        return ResponseEntity.ok(isValid);
    }

    @GetMapping("/customer/{customerId}/can-have-type/{policyType}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Boolean> canCustomerHavePolicy(@PathVariable Long customerId,
                                                         @PathVariable String policyType) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) checking if customer {} can have policy type: {}",
                currentUser, viewerRole, customerId, policyType);

        try {
            PolicyType type = PolicyType.valueOf(policyType.toUpperCase());
            boolean canHave = policyService.canCustomerHavePolicy(customerId, type);
            return ResponseEntity.ok(canHave);
        } catch (IllegalArgumentException e) {
            log.error("Invalid policy type provided: {}", policyType);
            return ResponseEntity.badRequest().build();
        }
    }

    // BULK OPERATIONS

    @PostMapping("/bulk-create")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PolicyDto>> createMultiplePolicies(
            @Valid @RequestBody List<PolicyDto> policies,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        log.info("Admin {} creating {} policies in bulk (unmask: {})",
                currentUser, policies.size(), unmask);

        List<PolicyDto> createdPolicies = policyService.createMultiplePolicies(policies);

        // Apply masking to response
        if (!unmask) {
            createdPolicies = maskingService.maskPolicyDataList(createdPolicies, "ADMIN", currentUser);
        }

        log.info("Bulk policy creation completed. Created: {} out of {}",
                createdPolicies.size(), policies.size());
        return ResponseEntity.status(HttpStatus.CREATED).body(createdPolicies);
    }

    @PatchMapping("/bulk-status-update")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> bulkUpdateStatus(@RequestParam List<Long> policyIds,
                                                   @RequestParam String status) {
        String currentUser = getCurrentUsername();
        log.info("Admin {} updating status to {} for {} policies",
                currentUser, status, policyIds.size());

        try {
            PolicyStatus policyStatus = PolicyStatus.valueOf(status.toUpperCase());
            policyService.bulkUpdateStatus(policyIds, policyStatus);

            return ResponseEntity.ok("Bulk status update completed successfully");
        } catch (IllegalArgumentException e) {
            log.error("Invalid policy status provided: {}", status);
            return ResponseEntity.badRequest().body("Invalid policy status: " + status);
        }
    }

    @PostMapping("/bulk-notifications")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> bulkSendNotifications(@RequestParam List<Long> policyIds,
                                                        @RequestParam String notificationType) {
        String currentUser = getCurrentUsername();
        log.info("Admin {} sending {} notifications for {} policies",
                currentUser, notificationType, policyIds.size());

        policyService.bulkSendNotifications(policyIds, notificationType);

        return ResponseEntity.ok("Bulk notifications sent successfully");
    }

    // INTEGRATION WITH CLAIMS

    @GetMapping("/{id}/claims-summary")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<Map<String, Object>> getClaimsSummary(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claims summary for policy ID: {} (unmask: {})",
                currentUser, viewerRole, id, unmask);

        BigDecimal totalClaimsAmount = policyService.getTotalClaimsAmount(id);

        // Apply financial masking if needed
        if (!unmask && shouldMaskFinancialData(viewerRole)) {
            String masked = dataMaskingUtil.maskAmount(totalClaimsAmount.doubleValue());
            totalClaimsAmount = new BigDecimal(masked.replace("*", "0"));
        }

        Map<String, Object> claimsSummary = Map.of(
                "totalClaims", policyService.getTotalClaimsCount(id),
                "totalClaimsAmount", totalClaimsAmount,
                "hasPendingClaims", policyService.hasPendingClaims(id)
        );

        return ResponseEntity.ok(claimsSummary);
    }

    // NEW MASKING UTILITY ENDPOINTS

    @GetMapping("/masking-info")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<Map<String, Object>> getMaskingInfo() {
        String viewerRole = getCurrentUserRole();

        return ResponseEntity.ok(Map.of(
                "viewerRole", viewerRole,
                "canUnmask", canUnmaskData(viewerRole),
                "maskingEnabled", true,
                "supportedMaskingTypes", List.of("EMAIL", "PHONE", "NAME", "FINANCIAL", "POLICY_NUMBER")
        ));
    }

    @GetMapping("/test-masking")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> testMasking() {
        // Test masking functionality
        String email = "customer@example.com";
        String policyNumber = "POL-2024-001";
        Double premium = 1200.50;

        return ResponseEntity.ok(Map.of(
                "original", Map.of(
                        "email", email,
                        "policyNumber", policyNumber,
                        "premium", premium
                ),
                "masked", Map.of(
                        "email", dataMaskingUtil.maskEmail(email),
                        "policyNumber", dataMaskingUtil.maskPolicyNumber(policyNumber),
                        "premium", dataMaskingUtil.maskAmount(premium)
                ),
                "viewerRole", getCurrentUserRole()
        ));
    }

    // UTILITY METHODS

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "ANONYMOUS";
    }

    private String getCurrentUserRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getAuthorities() != null) {
            return authentication.getAuthorities().stream()
                    .findFirst()
                    .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                    .orElse("CUSTOMER");
        }
        return "CUSTOMER";
    }

    private boolean canUnmaskData(String role) {
        return "ADMIN".equals(role);
    }

    private boolean isViewerOwnPolicy(PolicyDto policy, String viewerUsername, String viewerRole) {
        if (!"CUSTOMER".equals(viewerRole)) {
            return false; // Only customers have "own" policies
        }

        // Check if the viewer owns this policy
        return policy.getCustomerUsername() != null &&
                policy.getCustomerUsername().equals(viewerUsername);
    }

    private boolean shouldMaskFinancialData(String viewerRole, Long customerId, String currentUser) {
        if ("ADMIN".equals(viewerRole)) {
            return false; // Admin sees all financial data
        }
        if ("AGENT".equals(viewerRole)) {
            return false; // Agent sees financial data
        }
        // For customers, check if it's their own data
        return !"CUSTOMER".equals(viewerRole) || !isViewerOwnCustomer(customerId, currentUser);
    }

    private boolean shouldMaskFinancialData(String viewerRole) {
        return !"ADMIN".equals(viewerRole) && !"AGENT".equals(viewerRole);
    }

    private boolean isViewerOwnCustomer(Long customerId, String viewerUsername) {
        // This would need to be implemented based on your User-Customer relationship
        // For now, assume it's implemented in your service layer
        return policyService.isCustomerOwnedByUser(customerId, viewerUsername);
    }

    private String getPolicyMaskingSummary(PolicyDto policyDto) {
        StringBuilder summary = new StringBuilder();
        summary.append("Fields: ");
        summary.append("policyNumber=").append(isMaskedData(policyDto.getPolicyNumber()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("customerName=").append(isMaskedData(policyDto.getCustomerName()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("customerEmail=").append(isMaskedData(policyDto.getCustomerEmail()) ? "MASKED" : "CLEAR");
        return summary.toString();
    }

    private boolean isMaskedData(String data) {
        return data != null && data.contains("*");
    }
}
