// src/main/java/com/example/policy360/service/Impl/PolicyServiceImpl.java
package com.example.policy360.service.Impl;

import com.example.policy360.dto.PolicyDto;
import com.example.policy360.dto.PolicyStatisticsDto;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.PolicyType;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.exception.BusinessLogicException;
import com.example.policy360.exception.PolicyNotFoundException;
import com.example.policy360.exception.UserNotFoundException;
import com.example.policy360.repository.ClaimRepository;
import com.example.policy360.repository.PolicyRepository;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.service.EmailService;
import com.example.policy360.service.PolicyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PolicyServiceImpl implements PolicyService {

    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;
    private final ClaimRepository claimRepository;
    private final EmailService emailService;

    // Business constants
    private static final int MAX_POLICIES_PER_CUSTOMER = 10;
    private static final int EXPIRATION_REMINDER_DAYS = 30;
    private static final int RENEWAL_REMINDER_DAYS = 60;
    private static final BigDecimal MIN_PREMIUM_AMOUNT = new BigDecimal("100.00");
    private static final BigDecimal MIN_COVERAGE_AMOUNT = new BigDecimal("1000.00");
    private static final BigDecimal MAX_COVERAGE_AMOUNT = new BigDecimal("10000000.00");

    // BASIC CRUD OPERATIONS

    @Override
    public PolicyDto createPolicy(PolicyDto policyDto) {
        log.info("Creating new policy for customer ID: {}", policyDto.getCustomerId());

        // Comprehensive validation
        validatePolicyCreationRequest(policyDto);

        // Validate customer exists and has CUSTOMER role
        User customer = userRepository.findById(policyDto.getCustomerId())
                .orElseThrow(() -> new UserNotFoundException("Customer not found with ID: " + policyDto.getCustomerId()));

        if (customer.getRole() != Role.CUSTOMER) {
            throw new BusinessLogicException("User with ID " + policyDto.getCustomerId() +
                    " is not a customer. Role: " + customer.getRole());
        }

        // Business rule validations
        validateCustomerPolicyLimit(customer.getId());
        validatePolicyNumber(policyDto.getPolicyNumber());
        validatePolicyTypeForCustomer(customer.getId(), policyDto.getPolicyType());

        Policy policy = mapToEntity(policyDto);
        policy.setCustomer(customer);
        policy.setCreatedBy(getCurrentUsername());
        policy.setUpdatedBy(getCurrentUsername());

        // Apply business rules for new policy
        applyNewPolicyBusinessRules(policy);

        Policy savedPolicy = policyRepository.save(policy);
        log.info("Policy created successfully with ID: {} and number: {}",
                savedPolicy.getId(), savedPolicy.getPolicyNumber());

        // Send notification
        sendPolicyCreatedNotification(savedPolicy);

        return mapToDto(savedPolicy);
    }

    @Override
    @Transactional(readOnly = true)
    public PolicyDto getPolicyById(Long id) {
        log.info("Fetching policy with ID: {}", id);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        validateUserAccessToPolicy(policy);
        return enrichPolicyDto(mapToDto(policy));
    }

    @Override
    @Transactional(readOnly = true)
    public PolicyDto getPolicyByNumber(String policyNumber) {
        log.info("Fetching policy with number: {}", policyNumber);

        if (policyNumber == null || policyNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Policy number is required");
        }

        Policy policy = policyRepository.findByPolicyNumber(policyNumber)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with number: " + policyNumber));

        validateUserAccessToPolicy(policy);
        return enrichPolicyDto(mapToDto(policy));
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PolicyDto> getAllPolicies(Pageable pageable) {
        log.info("Fetching all policies with pagination - page: {}, size: {}",
                pageable.getPageNumber(), pageable.getPageSize());

        User currentUser = getCurrentUser();
        Page<Policy> policies;

        if (currentUser.getRole() == Role.ADMIN || currentUser.getRole() == Role.AGENT) {
            policies = policyRepository.findAll(pageable);
        } else {
            policies = policyRepository.findByCustomerId(currentUser.getId(), pageable);
        }

        return policies.map(policy -> enrichPolicyDto(mapToDto(policy)));
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getAllPolicies() {
        log.info("Fetching all policies without pagination");

        User currentUser = getCurrentUser();
        List<Policy> policies;

        if (currentUser.getRole() == Role.ADMIN || currentUser.getRole() == Role.AGENT) {
            policies = policyRepository.findAll();
        } else {
            policies = policyRepository.findByCustomerId(currentUser.getId());
        }

        return policies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    public PolicyDto updatePolicy(Long id, PolicyDto policyDto) {
        log.info("Updating policy with ID: {}", id);

        validatePolicyId(id);

        Policy existingPolicy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        validateUserAccessToPolicy(existingPolicy);

        if (!existingPolicy.getStatus().canBeModified()) {
            throw new BusinessLogicException("Cannot update policy with status: " + existingPolicy.getStatus());
        }

        // Store original values for audit
        PolicyType originalType = existingPolicy.getPolicyType();
        BigDecimal originalPremium = existingPolicy.getPremiumAmount();

        updatePolicyFields(existingPolicy, policyDto);
        existingPolicy.setUpdatedBy(getCurrentUsername());

        // Apply business rules for updates
        applyUpdateBusinessRules(existingPolicy, originalType, originalPremium);

        Policy updatedPolicy = policyRepository.save(existingPolicy);
        log.info("Policy updated successfully with ID: {}", updatedPolicy.getId());

        // Send notification if significant change
        if (isSignificantUpdate(originalPremium, existingPolicy.getPremiumAmount())) {
            sendPolicyUpdateNotification(updatedPolicy);
        }

        return enrichPolicyDto(mapToDto(updatedPolicy));
    }

    @Override
    public void deletePolicy(Long id) {
        log.info("Deleting policy with ID: {}", id);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        User currentUser = getCurrentUser();
        if (currentUser.getRole() != Role.ADMIN) {
            throw new BusinessLogicException("Only administrators can delete policies");
        }

        if (policy.getStatus().isTerminal()) {
            throw new BusinessLogicException("Cannot delete policy with terminal status: " + policy.getStatus());
        }

        if (hasPendingClaims(policy.getId())) {
            throw new BusinessLogicException("Cannot delete policy with pending claims");
        }

        // Soft delete - change status instead of hard delete
        policy.setStatus(PolicyStatus.TERMINATED);
        policy.setUpdatedBy(getCurrentUsername());
        policyRepository.save(policy);

        log.info("Policy soft-deleted (terminated) successfully with ID: {}", id);
    }

    // CUSTOMER-RELATED OPERATIONS

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getPoliciesByCustomerId(Long customerId) {
        log.info("Fetching policies for customer ID: {}", customerId);

        validateCustomerId(customerId);
        validateUserAccessToCustomer(customerId);

        List<Policy> policies = policyRepository.findByCustomerId(customerId);
        return policies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PolicyDto> getPoliciesByCustomerId(Long customerId, Pageable pageable) {
        log.info("Fetching policies for customer ID: {} with pagination", customerId);

        validateCustomerId(customerId);
        validateUserAccessToCustomer(customerId);

        Page<Policy> policies = policyRepository.findByCustomerId(customerId, pageable);
        return policies.map(policy -> enrichPolicyDto(mapToDto(policy)));
    }

    @Override
    @Transactional(readOnly = true)
    public BigDecimal getTotalPremiumByCustomer(Long customerId) {
        log.info("Calculating total premium for customer: {}", customerId);

        validateCustomerId(customerId);

        return policyRepository.getTotalPremiumByCustomerAndStatus(customerId, PolicyStatus.ACTIVE);
    }

    @Override
    public boolean isCustomerOwnedByUser(Long customerId, String username) {
        log.debug("Checking if customer {} is owned by user {}", customerId, username);

        try {
            // Find the user by username
            Optional<User> userOptional = userRepository.findByUsername(username);
            if (userOptional.isEmpty()) {
                log.debug("User {} not found", username);
                return false;
            }

            User user = userOptional.get();

            // Check ownership based on your User-Customer relationship
            // Option 1: If User entity has a direct customerId field
            if (user.getCustomerId() != null) {
                boolean isOwned = user.getCustomerId().equals(customerId);
                log.debug("Customer {} ownership check for user {}: {}", customerId, username, isOwned);
                return isOwned;
            }

            // Option 2: If you have a separate Customer entity with userId field
            // You would need to inject CustomerRepository and check:
            // Optional<Customer> customer = customerRepository.findById(customerId);
            // return customer.isPresent() && customer.get().getUserId().equals(user.getId());

            // Option 3: If User has a collection of customers
            // return user.getCustomers().stream().anyMatch(c -> c.getId().equals(customerId));

            log.debug("No customer relationship found for user {}", username);
            return false;

        } catch (Exception e) {
            log.error("Error checking customer ownership: {}", e.getMessage(), e);
            return false;
        }
    }

    // SEARCH AND FILTERING

    @Override
    @Transactional(readOnly = true)
    public Page<PolicyDto> searchPolicies(String policyNumber, String policyType, String status, Long customerId, Pageable pageable) {
        log.info("Searching policies with filters - policyNumber: {}, policyType: {}, status: {}, customerId: {}",
                policyNumber, policyType, status, customerId);

        PolicyType policyTypeEnum = null;
        PolicyStatus statusEnum = null;

        try {
            if (policyType != null && !policyType.trim().isEmpty()) {
                policyTypeEnum = PolicyType.valueOf(policyType.toUpperCase());
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid policy type provided: {}", policyType);
        }

        try {
            if (status != null && !status.trim().isEmpty()) {
                statusEnum = PolicyStatus.valueOf(status.toUpperCase());
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid policy status provided: {}", status);
        }

        Page<Policy> policies = policyRepository.searchPolicies(policyNumber, policyTypeEnum, statusEnum, customerId, pageable);
        return policies.map(policy -> enrichPolicyDto(mapToDto(policy)));
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getPoliciesByType(PolicyType policyType) {
        log.info("Fetching policies with type: {}", policyType);

        List<Policy> policies = policyRepository.findByPolicyType(policyType);
        return policies.stream()
                .filter(this::hasAccessToPolicy)
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getPoliciesByStatus(PolicyStatus status) {
        log.info("Fetching policies with status: {}", status);

        List<Policy> policies = policyRepository.findByStatus(status);
        return policies.stream()
                .filter(this::hasAccessToPolicy)
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Page<PolicyDto> getPoliciesByStatus(PolicyStatus status, Pageable pageable) {
        log.info("Fetching policies with status: {} with pagination", status);

        Page<Policy> policies = policyRepository.findByStatus(status, pageable);
        return policies.map(policy -> enrichPolicyDto(mapToDto(policy)));
    }

    // BUSINESS OPERATIONS

    @Override
    public PolicyDto updatePolicyStatus(Long id, String status) {
        log.info("Updating policy status for ID: {} to status: {}", id, status);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        User currentUser = getCurrentUser();
        if (currentUser.getRole() == Role.CUSTOMER) {
            throw new BusinessLogicException("Customers cannot update policy status");
        }

        try {
            PolicyStatus currentStatus = policy.getStatus();
            PolicyStatus newStatus = PolicyStatus.valueOf(status.toUpperCase());

            validateStatusTransition(currentStatus, newStatus);

            policy.setStatus(newStatus);
            policy.setUpdatedBy(getCurrentUsername());

            handleStatusChange(policy, currentStatus, newStatus);

            Policy updatedPolicy = policyRepository.save(policy);
            log.info("Policy status updated successfully for ID: {} from {} to {}",
                    id, currentStatus, newStatus);

            return enrichPolicyDto(mapToDto(updatedPolicy));

        } catch (IllegalArgumentException e) {
            log.error("Invalid policy status provided: {}", status);
            throw new BusinessLogicException("Invalid policy status: " + status + ". Valid statuses are: " +
                    Arrays.toString(PolicyStatus.values()));
        }
    }

    @Override
    public PolicyDto renewPolicy(Long id) {
        return renewPolicy(id, null);
    }

    @Override
    public PolicyDto renewPolicy(Long id, PolicyDto updates) {
        log.info("Renewing policy with ID: {}", id);

        validatePolicyId(id);

        Policy existingPolicy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (!existingPolicy.isEligibleForRenewal()) {
            throw new BusinessLogicException("Policy is not eligible for renewal");
        }

        // Create renewed policy
        Policy renewedPolicy = createRenewedPolicy(existingPolicy, updates);

        // Update original policy to expired
        existingPolicy.setStatus(PolicyStatus.EXPIRED);
        existingPolicy.setUpdatedBy(getCurrentUsername());
        policyRepository.save(existingPolicy);

        // Save new policy
        renewedPolicy.setCreatedBy(getCurrentUsername());
        renewedPolicy.setUpdatedBy(getCurrentUsername());
        Policy savedRenewal = policyRepository.save(renewedPolicy);

        log.info("Policy renewed successfully. Old policy: {}, New policy: {}",
                existingPolicy.getId(), savedRenewal.getId());

        // Send notification
        sendPolicyRenewalNotification(savedRenewal);

        return enrichPolicyDto(mapToDto(savedRenewal));
    }

    @Override
    public void cancelPolicy(Long id, String reason) {
        log.info("Cancelling policy with ID: {} - Reason: {}", id, reason);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (policy.getStatus() != PolicyStatus.ACTIVE) {
            throw new BusinessLogicException("Only active policies can be cancelled");
        }

        policy.setStatus(PolicyStatus.CANCELLED);
        policy.setUpdatedBy(getCurrentUsername());
        policyRepository.save(policy);

        // Send notification
        sendPolicyCancellationNotification(policy, reason);

        log.info("Policy cancelled successfully with ID: {}", id);
    }

    @Override
    public void suspendPolicy(Long id, String reason) {
        log.info("Suspending policy with ID: {} - Reason: {}", id, reason);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (policy.getStatus() != PolicyStatus.ACTIVE) {
            throw new BusinessLogicException("Only active policies can be suspended");
        }

        policy.setStatus(PolicyStatus.SUSPENDED);
        policy.setUpdatedBy(getCurrentUsername());
        policyRepository.save(policy);

        log.info("Policy suspended successfully with ID: {}", id);
    }

    @Override
    public void reactivatePolicy(Long id) {
        log.info("Reactivating policy with ID: {}", id);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (policy.getStatus() != PolicyStatus.SUSPENDED) {
            throw new BusinessLogicException("Only suspended policies can be reactivated");
        }

        if (policy.isExpired()) {
            throw new BusinessLogicException("Cannot reactivate expired policy");
        }

        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setUpdatedBy(getCurrentUsername());
        policyRepository.save(policy);

        log.info("Policy reactivated successfully with ID: {}", id);
    }

    // EXPIRATION AND RENEWAL MANAGEMENT

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getExpiringPolicies(int days) {
        log.info("Fetching policies expiring within {} days", days);

        LocalDate cutoffDate = LocalDate.now().plusDays(days);
        List<Policy> expiringPolicies = policyRepository.findByEndDateBeforeAndStatus(cutoffDate, PolicyStatus.ACTIVE);

        return expiringPolicies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getPoliciesEligibleForRenewal() {
        log.info("Fetching policies eligible for renewal");

        LocalDate renewalDate = LocalDate.now().plusDays(RENEWAL_REMINDER_DAYS);
        List<Policy> policies = policyRepository.findPoliciesEligibleForRenewal(renewalDate);

        return policies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getPoliciesNearRenewal(int days) {
        log.info("Fetching policies near renewal within {} days", days);

        LocalDate renewalDate = LocalDate.now().plusDays(days);
        List<Policy> policies = policyRepository.findByRenewalDateBeforeAndStatus(renewalDate, PolicyStatus.ACTIVE);

        return policies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    @Override
    @Async
    public void sendExpirationReminders() {
        log.info("Sending expiration reminders");

        List<PolicyDto> expiringPolicies = getExpiringPolicies(EXPIRATION_REMINDER_DAYS);

        for (PolicyDto policy : expiringPolicies) {
            try {
                Policy policyEntity = policyRepository.findById(policy.getId()).orElse(null);
                if (policyEntity != null) {
                    emailService.sendPolicyExpirationReminderEmail(policyEntity, (int) policy.getDaysUntilExpiry());
                }
            } catch (Exception e) {
                log.error("Failed to send expiration reminder for policy: {}", policy.getPolicyNumber(), e);
            }
        }

        log.info("Expiration reminders sent for {} policies", expiringPolicies.size());
    }

    @Override
    @Async
    public void sendRenewalReminders() {
        log.info("Sending renewal reminders");

        List<PolicyDto> renewalPolicies = getPoliciesEligibleForRenewal();

        for (PolicyDto policy : renewalPolicies) {
            try {
                Policy policyEntity = policyRepository.findById(policy.getId()).orElse(null);
                if (policyEntity != null) {
                    emailService.sendPolicyRenewalEmail(policyEntity);
                }
            } catch (Exception e) {
                log.error("Failed to send renewal reminder for policy: {}", policy.getPolicyNumber(), e);
            }
        }

        log.info("Renewal reminders sent for {} policies", renewalPolicies.size());
    }

    // PREMIUM AND COVERAGE OPERATIONS

    @Override
    public BigDecimal calculateRenewalPremium(Long policyId, PolicyDto updates) {
        log.info("Calculating renewal premium for policy: {}", policyId);

        Policy policy = policyRepository.findById(policyId)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + policyId));

        BigDecimal basePremium = policy.getPremiumAmount();

        // Apply business rules for renewal premium calculation
        // Example: 5% increase for renewal, adjustments based on claims history
        BigDecimal renewalMultiplier = BigDecimal.valueOf(1.05); // 5% increase

        // Adjust based on claims
        int claimsCount = getTotalClaimsCount(policyId);
        if (claimsCount > 2) {
            renewalMultiplier = renewalMultiplier.add(BigDecimal.valueOf(0.10)); // Additional 10% for multiple claims
        }

        BigDecimal renewalPremium = basePremium.multiply(renewalMultiplier);

        // Apply updates if provided
        if (updates != null && updates.getPremiumAmount() != null) {
            renewalPremium = updates.getPremiumAmount();
        }

        return renewalPremium.setScale(2, BigDecimal.ROUND_HALF_UP);
    }

    @Override
    public PolicyDto adjustPremium(Long id, BigDecimal newPremiumAmount, String reason) {
        log.info("Adjusting premium for policy ID: {} to amount: {} - Reason: {}", id, newPremiumAmount, reason);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (!policy.getStatus().canBeModified()) {
            throw new BusinessLogicException("Cannot adjust premium for policy with status: " + policy.getStatus());
        }

        if (newPremiumAmount.compareTo(MIN_PREMIUM_AMOUNT) < 0) {
            throw new BusinessLogicException("Premium amount cannot be less than " + MIN_PREMIUM_AMOUNT);
        }

        BigDecimal oldPremium = policy.getPremiumAmount();
        policy.setPremiumAmount(newPremiumAmount);
        policy.setUpdatedBy(getCurrentUsername());

        Policy savedPolicy = policyRepository.save(policy);

        log.info("Premium adjusted from {} to {} for policy: {}", oldPremium, newPremiumAmount, policy.getPolicyNumber());

        return enrichPolicyDto(mapToDto(savedPolicy));
    }

    @Override
    public PolicyDto adjustCoverage(Long id, BigDecimal newCoverageAmount, String reason) {
        log.info("Adjusting coverage for policy ID: {} to amount: {} - Reason: {}", id, newCoverageAmount, reason);

        validatePolicyId(id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        if (!policy.getStatus().canBeModified()) {
            throw new BusinessLogicException("Cannot adjust coverage for policy with status: " + policy.getStatus());
        }

        if (newCoverageAmount.compareTo(MIN_COVERAGE_AMOUNT) < 0) {
            throw new BusinessLogicException("Coverage amount cannot be less than " + MIN_COVERAGE_AMOUNT);
        }

        if (newCoverageAmount.compareTo(MAX_COVERAGE_AMOUNT) > 0) {
            throw new BusinessLogicException("Coverage amount cannot exceed " + MAX_COVERAGE_AMOUNT);
        }

        BigDecimal oldCoverage = policy.getCoverageAmount();
        policy.setCoverageAmount(newCoverageAmount);
        policy.setUpdatedBy(getCurrentUsername());

        Policy savedPolicy = policyRepository.save(policy);

        log.info("Coverage adjusted from {} to {} for policy: {}", oldCoverage, newCoverageAmount, policy.getPolicyNumber());

        return enrichPolicyDto(mapToDto(savedPolicy));
    }

    // STATISTICS AND REPORTING

    @Override
    @Transactional(readOnly = true)
    public PolicyStatisticsDto getPolicyStatistics() {
        log.info("Fetching policy statistics");

        long totalPolicies = policyRepository.count();
        long activePolicies = policyRepository.findByStatus(PolicyStatus.ACTIVE).size();
        long expiredPolicies = policyRepository.findByStatus(PolicyStatus.EXPIRED).size();

        Map<String, Long> policyCountByStatus = getPolicyCountByStatus();
        Map<String, Long> policyCountByType = getPolicyCountByType();

        return PolicyStatisticsDto.builder()
                .totalPolicies(totalPolicies)
                .activePolicies(activePolicies)
                .expiredPolicies(expiredPolicies)
                .policyCountByStatus(policyCountByStatus)
                .policyCountByType(policyCountByType)
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Long> getPolicyCountByStatus() {
        log.info("Fetching policy count by status");

        Map<String, Long> statusCount = new HashMap<>();
        for (PolicyStatus status : PolicyStatus.values()) {
            long count = policyRepository.findByStatus(status).size();
            statusCount.put(status.name(), count);
        }
        return statusCount;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Long> getPolicyCountByType() {
        log.info("Fetching policy count by type");

        List<Object[]> results = policyRepository.countPoliciesByTypeAndStatus(PolicyStatus.ACTIVE);
        Map<String, Long> typeCount = new HashMap<>();

        for (Object[] result : results) {
            PolicyType type = (PolicyType) result[0];
            Long count = (Long) result[1];
            typeCount.put(type.name(), count);
        }

        return typeCount;
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, BigDecimal> getRevenueBykeyType() {
        log.info("Fetching revenue by policy type");

        Map<String, BigDecimal> revenueByType = new HashMap<>();

        for (PolicyType type : PolicyType.values()) {
            BigDecimal averagePremium = policyRepository.getAveragePremiumByPolicyType(type);
            if (averagePremium != null) {
                long count = policyRepository.findByPolicyType(type).size();
                BigDecimal totalRevenue = averagePremium.multiply(BigDecimal.valueOf(count));
                revenueByType.put(type.name(), totalRevenue);
            }
        }

        return revenueByType;
    }

    @Override
    @Transactional(readOnly = true)
    public List<PolicyDto> getTopPoliciesByPremium(int limit) {
        log.info("Fetching top {} policies by premium", limit);

        List<Policy> policies = policyRepository.findAll().stream()
                .sorted((p1, p2) -> p2.getPremiumAmount().compareTo(p1.getPremiumAmount()))
                .limit(limit)
                .collect(Collectors.toList());

        return policies.stream()
                .map(this::mapToDto)
                .map(this::enrichPolicyDto)
                .collect(Collectors.toList());
    }

    // VALIDATION AND BUSINESS RULES

    @Override
    public boolean validatePolicy(PolicyDto policyDto) {
        try {
            validatePolicyCreationRequest(policyDto);
            return true;
        } catch (Exception e) {
            log.warn("Policy validation failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> getAvailablePolicyTypes() {
        log.info("Fetching available policy types");
        return Arrays.stream(PolicyType.values())
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<String> getAvailablePolicyStatuses() {
        log.info("Fetching available policy statuses");
        return Arrays.stream(PolicyStatus.values())
                .map(Enum::name)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean canCustomerHavePolicy(Long customerId, PolicyType policyType) {
        log.info("Checking if customer {} can have policy type: {}", customerId, policyType);

        // Business rule: Customer can only have one active policy per type
        return !policyRepository.existsByCustomerIdAndPolicyTypeAndStatus(customerId, policyType, PolicyStatus.ACTIVE);
    }

    // BULK OPERATIONS

    @Override
    public List<PolicyDto> createMultiplePolicies(List<PolicyDto> policies) {
        log.info("Creating multiple policies. Count: {}", policies.size());

        List<PolicyDto> createdPolicies = new ArrayList<>();

        for (PolicyDto policyDto : policies) {
            try {
                PolicyDto createdPolicy = createPolicy(policyDto);
                createdPolicies.add(createdPolicy);
            } catch (Exception e) {
                log.error("Failed to create policy with number: {}", policyDto.getPolicyNumber(), e);
            }
        }

        log.info("Successfully created {} out of {} policies", createdPolicies.size(), policies.size());
        return createdPolicies;
    }

    @Override
    public void bulkUpdateStatus(List<Long> policyIds, PolicyStatus status) {
        log.info("Bulk updating status to {} for {} policies", status, policyIds.size());

        for (Long policyId : policyIds) {
            try {
                updatePolicyStatus(policyId, status.name());
            } catch (Exception e) {
                log.error("Failed to update status for policy ID: {}", policyId, e);
            }
        }
    }

    @Override
    @Async
    public void bulkSendNotifications(List<Long> policyIds, String notificationType) {
        log.info("Bulk sending notifications of type {} for {} policies", notificationType, policyIds.size());

        for (Long policyId : policyIds) {
            try {
                Policy policy = policyRepository.findById(policyId).orElse(null);
                if (policy != null) {
                    sendNotificationByType(policy, notificationType);
                }
            } catch (Exception e) {
                log.error("Failed to send notification for policy ID: {}", policyId, e);
            }
        }
    }

    // INTEGRATION WITH CLAIMS

    @Override
    @Transactional(readOnly = true)
    public boolean hasPendingClaims(Long policyId) {
        return claimRepository.existsByPolicyId(policyId);
    }

    @Override
    @Transactional(readOnly = true)
    public BigDecimal getTotalClaimsAmount(Long policyId) {
        return claimRepository.findByPolicyId(policyId).stream()
                .map(claim -> claim.getClaimAmount())
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    @Override
    @Transactional(readOnly = true)
    public int getTotalClaimsCount(Long policyId) {
        return claimRepository.findByPolicyId(policyId).size();
    }

    // MAPPING METHODS

    private PolicyDto mapToDto(Policy policy) {
        try {
            return PolicyDto.builder()
                    .id(policy.getId())
                    .policyNumber(policy.getPolicyNumber())
                    .customerId(policy.getCustomer().getId())
                    .customerName(policy.getCustomer().getFullName())
                    .customerEmail(policy.getCustomer().getEmail())
                    .policyType(policy.getPolicyType().name())
                    .policyTypeDescription(policy.getPolicyType().getDescription())
                    .premiumAmount(policy.getPremiumAmount())
                    .coverageAmount(policy.getCoverageAmount())
                    .startDate(policy.getStartDate())
                    .endDate(policy.getEndDate())
                    .status(policy.getStatus().name())
                    .statusDescription(policy.getStatus().getDescription())
                    .deductibleAmount(policy.getDeductibleAmount())
                    .renewalDate(policy.getRenewalDate())
                    .policyTerms(policy.getPolicyTerms())
                    .beneficiaryName(policy.getBeneficiaryName())
                    .beneficiaryRelationship(policy.getBeneficiaryRelationship())
                    .agentCommissionRate(policy.getAgentCommissionRate())
                    .createdAt(policy.getCreatedAt())
                    .updatedAt(policy.getUpdatedAt())
                    .createdBy(policy.getCreatedBy())
                    .updatedBy(policy.getUpdatedBy())
                    .isExpired(policy.isExpired())
                    .canBeClaimed(policy.canBeClaimed())
                    .daysUntilExpiry(policy.getDaysUntilExpiry())
                    .isEligibleForRenewal(policy.isEligibleForRenewal())
                    .annualPremium(policy.calculateAnnualPremium())
                    .commissionAmount(policy.calculateCommissionAmount())
                    .coverageRatio(policy.getCoverageRatio())
                    .policyDurationInMonths(policy.getPolicyDurationInMonths())
                    .build();
        } catch (Exception e) {
            log.warn("Builder pattern failed, using setter approach for PolicyDto mapping: {}", e.getMessage());
            return mapToDtoWithSetters(policy);
        }
    }

    private PolicyDto mapToDtoWithSetters(Policy policy) {
        PolicyDto dto = new PolicyDto();
        dto.setId(policy.getId());
        dto.setPolicyNumber(policy.getPolicyNumber());
        dto.setCustomerId(policy.getCustomer().getId());
        dto.setCustomerName(policy.getCustomer().getFullName());
        dto.setCustomerEmail(policy.getCustomer().getEmail());
        dto.setPolicyType(policy.getPolicyType().name());
        dto.setPolicyTypeDescription(policy.getPolicyType().getDescription());
        dto.setPremiumAmount(policy.getPremiumAmount());
        dto.setCoverageAmount(policy.getCoverageAmount());
        dto.setStartDate(policy.getStartDate());
        dto.setEndDate(policy.getEndDate());
        dto.setStatus(policy.getStatus().name());
        dto.setStatusDescription(policy.getStatus().getDescription());
        dto.setDeductibleAmount(policy.getDeductibleAmount());
        dto.setRenewalDate(policy.getRenewalDate());
        dto.setPolicyTerms(policy.getPolicyTerms());
        dto.setBeneficiaryName(policy.getBeneficiaryName());
        dto.setBeneficiaryRelationship(policy.getBeneficiaryRelationship());
        dto.setAgentCommissionRate(policy.getAgentCommissionRate());
        dto.setCreatedAt(policy.getCreatedAt());
        dto.setUpdatedAt(policy.getUpdatedAt());
        dto.setCreatedBy(policy.getCreatedBy());
        dto.setUpdatedBy(policy.getUpdatedBy());
        dto.setExpired(policy.isExpired());
        dto.setCanBeClaimed(policy.canBeClaimed());
        dto.setDaysUntilExpiry(policy.getDaysUntilExpiry());
        dto.setEligibleForRenewal(policy.isEligibleForRenewal());
        dto.setAnnualPremium(policy.calculateAnnualPremium());
        dto.setCommissionAmount(policy.calculateCommissionAmount());
        dto.setCoverageRatio(policy.getCoverageRatio());
        dto.setPolicyDurationInMonths(policy.getPolicyDurationInMonths());
        return dto;
    }

    private Policy mapToEntity(PolicyDto dto) {
        try {
            return Policy.builder()
                    .policyNumber(dto.getPolicyNumber())
                    .policyType(PolicyType.valueOf(dto.getPolicyType()))
                    .premiumAmount(dto.getPremiumAmount())
                    .coverageAmount(dto.getCoverageAmount())
                    .startDate(dto.getStartDate())
                    .endDate(dto.getEndDate())
                    .status(PolicyStatus.ACTIVE)
                    .deductibleAmount(dto.getDeductibleAmount() != null ? dto.getDeductibleAmount() : BigDecimal.ZERO)
                    .renewalDate(dto.getRenewalDate())
                    .policyTerms(dto.getPolicyTerms())
                    .beneficiaryName(dto.getBeneficiaryName())
                    .beneficiaryRelationship(dto.getBeneficiaryRelationship())
                    .agentCommissionRate(dto.getAgentCommissionRate() != null ? dto.getAgentCommissionRate() : BigDecimal.valueOf(5.00))
                    .build();
        } catch (Exception e) {
            log.warn("Builder pattern failed, using setter approach for Policy mapping: {}", e.getMessage());
            return mapToEntityWithSetters(dto);
        }
    }

    private Policy mapToEntityWithSetters(PolicyDto dto) {
        Policy policy = new Policy();
        policy.setPolicyNumber(dto.getPolicyNumber());
        policy.setPolicyType(PolicyType.valueOf(dto.getPolicyType()));
        policy.setPremiumAmount(dto.getPremiumAmount());
        policy.setCoverageAmount(dto.getCoverageAmount());
        policy.setStartDate(dto.getStartDate());
        policy.setEndDate(dto.getEndDate());
        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setDeductibleAmount(dto.getDeductibleAmount() != null ? dto.getDeductibleAmount() : BigDecimal.ZERO);
        policy.setRenewalDate(dto.getRenewalDate());
        policy.setPolicyTerms(dto.getPolicyTerms());
        policy.setBeneficiaryName(dto.getBeneficiaryName());
        policy.setBeneficiaryRelationship(dto.getBeneficiaryRelationship());
        policy.setAgentCommissionRate(dto.getAgentCommissionRate() != null ? dto.getAgentCommissionRate() : BigDecimal.valueOf(5.00));
        return policy;
    }

    private PolicyDto enrichPolicyDto(PolicyDto dto) {
        if (dto.getId() != null) {
            dto.setTotalClaims(getTotalClaimsCount(dto.getId()));
            dto.setTotalClaimsAmount(getTotalClaimsAmount(dto.getId()));
            dto.setNearExpiry(dto.getDaysUntilExpiry() <= EXPIRATION_REMINDER_DAYS);
        }
        return dto;
    }

    // VALIDATION METHODS

    private void validatePolicyCreationRequest(PolicyDto policyDto) {
        if (policyDto == null) {
            throw new IllegalArgumentException("Policy data is required");
        }

        validateBasicPolicyData(policyDto);
        validatePolicyDates(policyDto.getStartDate(), policyDto.getEndDate());
        validatePolicyAmounts(policyDto.getPremiumAmount(), policyDto.getCoverageAmount());
        validatePolicyType(policyDto.getPolicyType());
    }

    private void validateBasicPolicyData(PolicyDto policyDto) {
        if (policyDto.getPolicyNumber() == null || policyDto.getPolicyNumber().trim().isEmpty()) {
            throw new IllegalArgumentException("Policy number is required");
        }

        if (policyDto.getPolicyNumber().length() < 5 || policyDto.getPolicyNumber().length() > 50) {
            throw new IllegalArgumentException("Policy number must be between 5 and 50 characters");
        }

        if (policyDto.getCustomerId() == null) {
            throw new IllegalArgumentException("Customer ID is required");
        }
    }

    private void validatePolicyAmounts(BigDecimal premiumAmount, BigDecimal coverageAmount) {
        if (premiumAmount == null || premiumAmount.compareTo(MIN_PREMIUM_AMOUNT) < 0) {
            throw new IllegalArgumentException("Premium amount must be at least " + MIN_PREMIUM_AMOUNT);
        }

        if (coverageAmount == null || coverageAmount.compareTo(MIN_COVERAGE_AMOUNT) < 0) {
            throw new IllegalArgumentException("Coverage amount must be at least " + MIN_COVERAGE_AMOUNT);
        }

        if (coverageAmount.compareTo(MAX_COVERAGE_AMOUNT) > 0) {
            throw new IllegalArgumentException("Coverage amount cannot exceed " + MAX_COVERAGE_AMOUNT);
        }

        // Business rule: Coverage should be reasonable multiple of premium
        BigDecimal coverageRatio = coverageAmount.divide(premiumAmount, 2, BigDecimal.ROUND_HALF_UP);
        if (coverageRatio.compareTo(new BigDecimal("1000")) > 0) {
            throw new BusinessLogicException("Coverage amount seems too high compared to premium. Please review the amounts.");
        }
    }

    private void validatePolicyDates(LocalDate startDate, LocalDate endDate) {
        if (startDate == null) {
            throw new IllegalArgumentException("Start date is required");
        }

        if (endDate == null) {
            throw new IllegalArgumentException("End date is required");
        }

        if (endDate.isBefore(startDate) || endDate.isEqual(startDate)) {
            throw new IllegalArgumentException("End date must be after start date");
        }

        if (startDate.isBefore(LocalDate.now().minusDays(30))) {
            throw new IllegalArgumentException("Start date cannot be more than 30 days in the past");
        }

        if (endDate.isAfter(LocalDate.now().plusYears(10))) {
            throw new IllegalArgumentException("End date cannot be more than 10 years in the future");
        }

        // Business rule: Minimum policy duration
        if (endDate.isBefore(startDate.plusMonths(6))) {
            throw new BusinessLogicException("Policy duration must be at least 6 months");
        }
    }

    private void validatePolicyType(String policyType) {
        if (policyType == null || policyType.trim().isEmpty()) {
            throw new IllegalArgumentException("Policy type is required");
        }

        try {
            PolicyType.valueOf(policyType.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid policy type: " + policyType +
                    ". Valid types are: " + Arrays.toString(PolicyType.values()));
        }
    }

    private void validateCustomerPolicyLimit(Long customerId) {
        long activePolicyCount = policyRepository.countByCustomerIdAndStatus(customerId, PolicyStatus.ACTIVE);
        if (activePolicyCount >= MAX_POLICIES_PER_CUSTOMER) {
            throw new BusinessLogicException("Customer has reached the maximum limit of " +
                    MAX_POLICIES_PER_CUSTOMER + " active policies");
        }
    }

    private void validatePolicyNumber(String policyNumber) {
        if (policyRepository.existsByPolicyNumber(policyNumber)) {
            throw new BusinessLogicException("Policy number already exists: " + policyNumber);
        }
    }

    private void validatePolicyTypeForCustomer(Long customerId, String policyType) {
        PolicyType type = PolicyType.valueOf(policyType);
        if (!canCustomerHavePolicy(customerId, type)) {
            throw new BusinessLogicException("Customer already has an active policy of type: " + type.getDescription());
        }
    }

    private void validatePolicyId(Long id) {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Policy ID must be a positive number");
        }
    }

    private void validateCustomerId(Long customerId) {
        if (customerId == null || customerId <= 0) {
            throw new IllegalArgumentException("Customer ID must be a positive number");
        }

        if (!userRepository.existsById(customerId)) {
            throw new UserNotFoundException("Customer not found with ID: " + customerId);
        }
    }

    private void validateUserAccessToPolicy(Policy policy) {
        User currentUser = getCurrentUser();

        if (currentUser.getRole() == Role.CUSTOMER &&
                !currentUser.getId().equals(policy.getCustomer().getId())) {
            throw new BusinessLogicException("Access denied: You can only view your own policies");
        }
    }

    private void validateUserAccessToCustomer(Long customerId) {
        User currentUser = getCurrentUser();
        if (currentUser.getRole() == Role.CUSTOMER && !currentUser.getId().equals(customerId)) {
            throw new BusinessLogicException("Customers can only access their own policies");
        }
    }

    private void validateStatusTransition(PolicyStatus currentStatus, PolicyStatus newStatus) {
        if (currentStatus == newStatus) {
            throw new BusinessLogicException("Policy is already in " + newStatus + " status");
        }

        boolean isValidTransition = switch (currentStatus) {
            case PENDING -> newStatus == PolicyStatus.ACTIVE || newStatus == PolicyStatus.CANCELLED;
            case ACTIVE -> newStatus == PolicyStatus.SUSPENDED || newStatus == PolicyStatus.CANCELLED ||
                    newStatus == PolicyStatus.EXPIRED || newStatus == PolicyStatus.INACTIVE;
            case SUSPENDED -> newStatus == PolicyStatus.ACTIVE || newStatus == PolicyStatus.CANCELLED ||
                    newStatus == PolicyStatus.INACTIVE;
            case INACTIVE -> newStatus == PolicyStatus.ACTIVE || newStatus == PolicyStatus.CANCELLED;
            case EXPIRED, CANCELLED, TERMINATED -> false; // Terminal states
        };

        if (!isValidTransition) {
            throw new BusinessLogicException(
                    String.format("Invalid status transition from %s to %s", currentStatus, newStatus));
        }
    }

    // BUSINESS LOGIC METHODS

    private void applyNewPolicyBusinessRules(Policy policy) {
        // Set default renewal date if not provided
        if (policy.getRenewalDate() == null) {
            policy.setRenewalDate(policy.getEndDate().minusMonths(1));
        }

        // Apply discounts based on policy type or customer profile
        applyPolicyDiscounts(policy);

        // Set default commission rate if not provided
        if (policy.getAgentCommissionRate() == null) {
            policy.setAgentCommissionRate(getDefaultCommissionRate(policy.getPolicyType()));
        }
    }

    private void applyUpdateBusinessRules(Policy policy, PolicyType originalType, BigDecimal originalPremium) {
        // If policy type changed, may need to recalculate premium
        if (!policy.getPolicyType().equals(originalType)) {
            log.info("Policy type changed from {} to {} for policy: {}",
                    originalType, policy.getPolicyType(), policy.getPolicyNumber());
        }

        // If premium increased significantly, may need approval
        if (policy.getPremiumAmount().compareTo(originalPremium.multiply(BigDecimal.valueOf(1.5))) > 0) {
            log.warn("Premium increased by more than 50% for policy: {}", policy.getPolicyNumber());
        }
    }

    private void applyPolicyDiscounts(Policy policy) {
        // Example: Health insurance discount for comprehensive coverage
        if (policy.getPolicyType() == PolicyType.COMPREHENSIVE_HEALTH) {
            log.info("Applying comprehensive health insurance processing for policy: {}", policy.getPolicyNumber());
        }
    }

    private BigDecimal getDefaultCommissionRate(PolicyType policyType) {
        return switch (policyType) {
            case LIFE_INSURANCE -> BigDecimal.valueOf(8.00);
            case HEALTH_INSURANCE, COMPREHENSIVE_HEALTH -> BigDecimal.valueOf(6.00);
            case AUTO_INSURANCE -> BigDecimal.valueOf(4.00);
            case HOME_INSURANCE -> BigDecimal.valueOf(5.00);
            case TRAVEL_INSURANCE -> BigDecimal.valueOf(3.00);
        };
    }

    private void updatePolicyFields(Policy existingPolicy, PolicyDto policyDto) {
        if (policyDto.getPolicyType() != null && !policyDto.getPolicyType().trim().isEmpty()) {
            validatePolicyType(policyDto.getPolicyType());
            existingPolicy.setPolicyType(PolicyType.valueOf(policyDto.getPolicyType()));
        }

        if (policyDto.getPremiumAmount() != null) {
            validatePolicyAmounts(policyDto.getPremiumAmount(),
                    policyDto.getCoverageAmount() != null ? policyDto.getCoverageAmount() : existingPolicy.getCoverageAmount());
            existingPolicy.setPremiumAmount(policyDto.getPremiumAmount());
        }

        if (policyDto.getCoverageAmount() != null) {
            validatePolicyAmounts(
                    policyDto.getPremiumAmount() != null ? policyDto.getPremiumAmount() : existingPolicy.getPremiumAmount(),
                    policyDto.getCoverageAmount());
            existingPolicy.setCoverageAmount(policyDto.getCoverageAmount());
        }

        if (policyDto.getStartDate() != null && policyDto.getEndDate() != null) {
            validatePolicyDates(policyDto.getStartDate(), policyDto.getEndDate());
            existingPolicy.setStartDate(policyDto.getStartDate());
            existingPolicy.setEndDate(policyDto.getEndDate());
        }

        // Update optional fields
        if (policyDto.getDeductibleAmount() != null) {
            existingPolicy.setDeductibleAmount(policyDto.getDeductibleAmount());
        }

        if (policyDto.getRenewalDate() != null) {
            existingPolicy.setRenewalDate(policyDto.getRenewalDate());
        }

        if (policyDto.getPolicyTerms() != null) {
            existingPolicy.setPolicyTerms(policyDto.getPolicyTerms());
        }

        if (policyDto.getBeneficiaryName() != null) {
            existingPolicy.setBeneficiaryName(policyDto.getBeneficiaryName());
        }

        if (policyDto.getBeneficiaryRelationship() != null) {
            existingPolicy.setBeneficiaryRelationship(policyDto.getBeneficiaryRelationship());
        }

        if (policyDto.getAgentCommissionRate() != null) {
            existingPolicy.setAgentCommissionRate(policyDto.getAgentCommissionRate());
        }
    }

    private void handleStatusChange(Policy policy, PolicyStatus oldStatus, PolicyStatus newStatus) {
        String currentUser = getCurrentUsername();

        switch (newStatus) {
            case EXPIRED -> {
                log.info("Policy {} marked as expired by user: {}", policy.getPolicyNumber(), currentUser);
            }
            case CANCELLED -> {
                log.info("Policy {} cancelled by user: {}", policy.getPolicyNumber(), currentUser);
            }
            case SUSPENDED -> {
                log.info("Policy {} suspended by user: {}", policy.getPolicyNumber(), currentUser);
            }
            case ACTIVE -> {
                if (oldStatus == PolicyStatus.PENDING) {
                    log.info("Policy {} activated from pending by user: {}", policy.getPolicyNumber(), currentUser);
                } else if (oldStatus == PolicyStatus.SUSPENDED) {
                    log.info("Policy {} reactivated from suspension by user: {}", policy.getPolicyNumber(), currentUser);
                }
            }
        }
    }

    private Policy createRenewedPolicy(Policy existingPolicy, PolicyDto updates) {
        Policy renewedPolicy = Policy.builder()
                .policyNumber(generateRenewalPolicyNumber(existingPolicy.getPolicyNumber()))
                .customer(existingPolicy.getCustomer())
                .policyType(existingPolicy.getPolicyType())
                .premiumAmount(calculateRenewalPremium(existingPolicy.getId(), updates))
                .coverageAmount(existingPolicy.getCoverageAmount())
                .startDate(existingPolicy.getEndDate().plusDays(1))
                .endDate(existingPolicy.getEndDate().plusYears(1))
                .status(PolicyStatus.ACTIVE)
                .deductibleAmount(existingPolicy.getDeductibleAmount())
                .policyTerms(existingPolicy.getPolicyTerms())
                .beneficiaryName(existingPolicy.getBeneficiaryName())
                .beneficiaryRelationship(existingPolicy.getBeneficiaryRelationship())
                .agentCommissionRate(existingPolicy.getAgentCommissionRate())
                .build();

        // Apply updates if provided
        if (updates != null) {
            if (updates.getPremiumAmount() != null) {
                renewedPolicy.setPremiumAmount(updates.getPremiumAmount());
            }
            if (updates.getCoverageAmount() != null) {
                renewedPolicy.setCoverageAmount(updates.getCoverageAmount());
            }
            if (updates.getDeductibleAmount() != null) {
                renewedPolicy.setDeductibleAmount(updates.getDeductibleAmount());
            }
        }

        return renewedPolicy;
    }

    private String generateRenewalPolicyNumber(String originalPolicyNumber) {
        // Add renewal suffix to original policy number
        return originalPolicyNumber + "-R" + System.currentTimeMillis() % 1000;
    }

    private boolean isSignificantUpdate(BigDecimal oldPremium, BigDecimal newPremium) {
        if (oldPremium == null || newPremium == null) {
            return false;
        }

        BigDecimal percentChange = newPremium.subtract(oldPremium)
                .divide(oldPremium, 4, BigDecimal.ROUND_HALF_UP)
                .multiply(BigDecimal.valueOf(100));

        return percentChange.abs().compareTo(BigDecimal.valueOf(10)) > 0; // 10% change threshold
    }

    private boolean hasAccessToPolicy(Policy policy) {
        try {
            validateUserAccessToPolicy(policy);
            return true;
        } catch (BusinessLogicException e) {
            return false;
        }
    }

    // NOTIFICATION METHODS

    private void sendPolicyCreatedNotification(Policy policy) {
        try {
            emailService.sendPolicyCreatedEmail(policy);
        } catch (Exception e) {
            log.error("Failed to send policy creation notification for policy: {}", policy.getPolicyNumber(), e);
        }
    }

    private void sendPolicyUpdateNotification(Policy policy) {
        try {
            // Could send a policy update email if implemented
            log.info("Policy update notification would be sent for: {}", policy.getPolicyNumber());
        } catch (Exception e) {
            log.error("Failed to send policy update notification for policy: {}", policy.getPolicyNumber(), e);
        }
    }

    private void sendPolicyRenewalNotification(Policy policy) {
        try {
            emailService.sendPolicyRenewalEmail(policy);
        } catch (Exception e) {
            log.error("Failed to send policy renewal notification for policy: {}", policy.getPolicyNumber(), e);
        }
    }

    private void sendPolicyCancellationNotification(Policy policy, String reason) {
        try {
            emailService.sendPolicyCancellationEmail(policy, reason);
        } catch (Exception e) {
            log.error("Failed to send policy cancellation notification for policy: {}", policy.getPolicyNumber(), e);
        }
    }

    private void sendNotificationByType(Policy policy, String notificationType) {
        try {
            switch (notificationType.toUpperCase()) {
                case "EXPIRATION" -> emailService.sendPolicyExpirationReminderEmail(policy, (int) policy.getDaysUntilExpiry());
                case "RENEWAL" -> emailService.sendPolicyRenewalEmail(policy);
                case "CREATION" -> emailService.sendPolicyCreatedEmail(policy);
                default -> log.warn("Unknown notification type: {}", notificationType);
            }
        } catch (Exception e) {
            log.error("Failed to send {} notification for policy: {}", notificationType, policy.getPolicyNumber(), e);
        }
    }

    // UTILITY METHODS

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "SYSTEM";
    }

    private User getCurrentUser() {
        String username = getCurrentUsername();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new BusinessLogicException("Current user not found: " + username));
    }
}
