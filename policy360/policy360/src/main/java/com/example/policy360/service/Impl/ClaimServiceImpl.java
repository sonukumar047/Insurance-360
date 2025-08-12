package com.example.policy360.service.Impl;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.dto.ClaimStatusUpdateDto;
import com.example.policy360.entity.Claim;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.exception.BusinessLogicException;
import com.example.policy360.exception.ClaimNotFoundException;
import com.example.policy360.exception.PolicyNotFoundException;
import com.example.policy360.repository.ClaimRepository;
import com.example.policy360.repository.PolicyRepository;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.service.ClaimService;
import com.example.policy360.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class ClaimServiceImpl implements ClaimService {

    private final ClaimRepository claimRepository;
    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    private static final int MAX_CLAIMS_PER_POLICY = 5;
    private static final int MAX_INCIDENT_DAYS_OLD = 365;

    @Override
    public ClaimDto createClaim(ClaimDto claimDto) {
        log.info("Creating new claim for policy ID: {}", claimDto.getPolicyId());

        // Comprehensive validation
        validateClaimCreationRequest(claimDto);

        // Validate policy exists and is active
        Policy policy = policyRepository.findById(claimDto.getPolicyId())
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + claimDto.getPolicyId()));

        validatePolicyForClaim(policy);

        // Check business rules
        validateClaimBusinessRules(claimDto, policy);

        // Create claim
        Claim claim = mapToEntity(claimDto);
        claim.setPolicy(policy);
        claim.setClaimNumber(generateClaimNumber());

        Claim savedClaim = claimRepository.save(claim);
        log.info("Claim created successfully with ID: {} and number: {}",
                savedClaim.getId(), savedClaim.getClaimNumber());

        // Send notification email
        try {
            emailService.sendClaimStatusUpdateEmail(savedClaim);
        } catch (Exception e) {
            log.error("Failed to send claim creation email for claim: {}", savedClaim.getClaimNumber(), e);
        }

        return mapToDto(savedClaim);
    }

    @Override
    @Transactional(readOnly = true)
    public ClaimDto getClaimById(Long id) {
        log.info("Fetching claim with ID: {}", id);

        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Claim ID must be a positive number");
        }

        Claim claim = claimRepository.findById(id)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + id));

        validateUserAccessToClaim(claim);
        return mapToDto(claim);
    }

    @Override
    @Transactional(readOnly = true)
    public ClaimDto getClaimByNumber(String claimNumber) {
        log.info("Fetching claim with number: {}", claimNumber);

        if (claimNumber == null || claimNumber.trim().isEmpty()) {
            throw new IllegalArgumentException("Claim number is required");
        }

        Claim claim = claimRepository.findByClaimNumber(claimNumber)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with number: " + claimNumber));

        validateUserAccessToClaim(claim);
        return mapToDto(claim);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ClaimDto> getAllClaims(Pageable pageable) {
        log.info("Fetching all claims with pagination - page: {}, size: {}",
                pageable.getPageNumber(), pageable.getPageSize());

        User currentUser = getCurrentUser();
        Page<Claim> claims;

        // Role-based filtering
        if (currentUser.getRole() == Role.ADMIN || currentUser.getRole() == Role.AGENT) {
            claims = claimRepository.findAll(pageable);
        } else {
            claims = claimRepository.findByCustomerId(currentUser.getId(), pageable);
        }

        return claims.map(this::mapToDto);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getAllClaims() {
        log.info("Fetching all claims without pagination");

        User currentUser = getCurrentUser();
        List<Claim> claims;

        if (currentUser.getRole() == Role.ADMIN || currentUser.getRole() == Role.AGENT) {
            claims = claimRepository.findAll();
        } else {
            claims = claimRepository.findByCustomerId(currentUser.getId());
        }

        return claims.stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    public ClaimDto updateClaimStatus(Long id, ClaimStatusUpdateDto statusUpdate) {
        log.info("Updating claim status for ID: {} to status: {}", id, statusUpdate.getStatus());

        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Claim ID must be a positive number");
        }

        Claim claim = claimRepository.findById(id)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + id));

        // Validate user permissions
        validateUserPermissionForStatusUpdate();

        try {
            ClaimStatus currentStatus = claim.getStatus();
            ClaimStatus newStatus = ClaimStatus.valueOf(statusUpdate.getStatus().toUpperCase());

            // Validate status transition
            validateStatusTransition(currentStatus, newStatus);

            // Update claim
            updateClaimWithNewStatus(claim, newStatus, statusUpdate);

            Claim updatedClaim = claimRepository.save(claim);
            log.info("Claim status updated successfully for ID: {} from {} to {}",
                    id, currentStatus, newStatus);

            // Send notification based on status
            sendStatusUpdateNotification(updatedClaim, currentStatus, newStatus);

            return mapToDto(updatedClaim);

        } catch (IllegalArgumentException e) {
            log.error("Invalid claim status provided: {}", statusUpdate.getStatus());
            throw new BusinessLogicException("Invalid claim status: " + statusUpdate.getStatus() +
                    ". Valid statuses are: " + Arrays.toString(ClaimStatus.values()));
        }
    }

    @Override
    public void deleteClaim(Long id) {
        log.info("Deleting claim with ID: {}", id);

        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Claim ID must be a positive number");
        }

        Claim claim = claimRepository.findById(id)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + id));

        // Only admin can delete claims
        User currentUser = getCurrentUser();
        if (currentUser.getRole() != Role.ADMIN) {
            throw new BusinessLogicException("Only administrators can delete claims");
        }

        // Business validation - only allow deletion for non-terminal claims
        if (claim.getStatus().isTerminal()) {
            throw new BusinessLogicException("Cannot delete claim with terminal status: " + claim.getStatus());
        }

        claimRepository.delete(claim);
        log.info("Claim deleted successfully with ID: {}", id);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getClaimsByPolicyId(Long policyId) {
        log.info("Fetching claims for policy ID: {}", policyId);

        if (policyId == null || policyId <= 0) {
            throw new IllegalArgumentException("Policy ID must be a positive number");
        }

        List<Claim> claims = claimRepository.findByPolicyId(policyId);
        return claims.stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getClaimsByCustomerId(Long customerId) {
        log.info("Fetching claims for customer ID: {}", customerId);

        if (customerId == null || customerId <= 0) {
            throw new IllegalArgumentException("Customer ID must be a positive number");
        }

        // Validate access permissions
        User currentUser = getCurrentUser();
        if (currentUser.getRole() == Role.CUSTOMER && !currentUser.getId().equals(customerId)) {
            throw new BusinessLogicException("Customers can only access their own claims");
        }

        List<Claim> claims = claimRepository.findByCustomerId(customerId);
        return claims.stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getClaimsByStatus(ClaimStatus status) {
        log.info("Fetching claims with status: {}", status);

        List<Claim> claims = claimRepository.findByStatus(status);
        return claims.stream()
                .filter(this::hasAccessToClaim)
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ClaimDto> getClaimsByStatus(ClaimStatus status, Pageable pageable) {
        log.info("Fetching claims with status: {} with pagination", status);

        Page<Claim> claims = claimRepository.findByStatus(status, pageable);
        return claims.map(this::mapToDto);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<ClaimDto> searchClaims(String claimNumber, String status, Long policyId, Pageable pageable) {
        log.info("Searching claims with filters - claimNumber: {}, status: {}, policyId: {}",
                claimNumber, status, policyId);

        Specification<Claim> spec = createBaseSpecification();

        if (claimNumber != null && !claimNumber.trim().isEmpty()) {
            spec = spec.and(createClaimNumberSpecification(claimNumber));
        }

        if (status != null && !status.trim().isEmpty()) {
            spec = spec.and(createStatusSpecification(status));
        }

        if (policyId != null) {
            spec = spec.and(createPolicyIdSpecification(policyId));
        }

        // Apply role-based filtering
        spec = spec.and(createRoleBasedSpecification());

        Page<Claim> claims = claimRepository.findAll(spec, pageable);
        return claims.map(this::mapToDto);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getPendingClaims() {
        log.info("Fetching pending claims");
        return getClaimsByStatus(ClaimStatus.PENDING);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ClaimDto> getClaimsForReminder(int daysOld) {
        log.info("Fetching claims for reminder - {} days old", daysOld);

        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysOld);
        List<Claim> claims = claimRepository.findByStatusAndSubmittedDateBefore(ClaimStatus.PENDING, cutoffDate);

        return claims.stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public BigDecimal getTotalClaimsAmountByPolicy(Long policyId) {
        log.info("Calculating total claims amount for policy: {}", policyId);

        List<Claim> claims = claimRepository.findByPolicyId(policyId);
        return claims.stream()
                .map(Claim::getClaimAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    @Override
    @Transactional(readOnly = true)
    public long getClaimsCountByStatus(ClaimStatus status) {
        log.info("Counting claims with status: {}", status);
        return claimRepository.findByStatus(status).size();
    }

    // BUSINESS OPERATIONS

    @Override
    public ClaimDto approveClaim(Long id, BigDecimal approvedAmount) {
        log.info("Approving claim with ID: {}", id);

        ClaimStatusUpdateDto statusUpdate = new ClaimStatusUpdateDto();
        statusUpdate.setStatus(ClaimStatus.APPROVED.name());
        statusUpdate.setApprovedAmount(approvedAmount);
        statusUpdate.setComments("Claim approved by " + getCurrentUsername());

        return updateClaimStatus(id, statusUpdate);
    }

    @Override
    public ClaimDto rejectClaim(Long id, String reason) {
        log.info("Rejecting claim with ID: {}", id);

        ClaimStatusUpdateDto statusUpdate = new ClaimStatusUpdateDto();
        statusUpdate.setStatus(ClaimStatus.REJECTED.name());
        statusUpdate.setRejectionReason(reason);
        statusUpdate.setComments("Claim rejected by " + getCurrentUsername());

        return updateClaimStatus(id, statusUpdate);
    }

    @Override
    public ClaimDto processClaim(Long id) {
        log.info("Processing claim with ID: {}", id);

        ClaimStatusUpdateDto statusUpdate = new ClaimStatusUpdateDto();
        statusUpdate.setStatus(ClaimStatus.PROCESSING.name());
        statusUpdate.setComments("Claim moved to processing by " + getCurrentUsername());

        return updateClaimStatus(id, statusUpdate);
    }

    // MAPPING METHODS

    private ClaimDto mapToDto(Claim claim) {
        try {
            return ClaimDto.builder()
                    .id(claim.getId())
                    .claimNumber(claim.getClaimNumber())
                    .policyId(claim.getPolicy().getId())
                    .policyNumber(claim.getPolicy().getPolicyNumber())
                    .customerName(claim.getPolicy().getCustomer().getFullName())
                    .description(claim.getDescription())
                    .claimAmount(claim.getClaimAmount())
                    .incidentDate(claim.getIncidentDate())
                    .status(claim.getStatus().name())
                    .statusDescription(claim.getStatus().getDescription())
                    .submittedDate(claim.getSubmittedDate())
                    .processedDate(claim.getProcessedDate())
                    .rejectionReason(claim.getRejectionReason())
                    .approvedAmount(claim.getApprovedAmount())
                    .createdAt(claim.getCreatedAt())
                    .updatedAt(claim.getUpdatedAt())
                    .canBeModified(claim.canBeProcessed())
                    .isWithinCoverageLimit(claim.isWithinCoverageLimit())
                    .daysSinceSubmission(claim.getDaysSinceSubmission())
                    .build();
        } catch (Exception e) {
            log.warn("Builder pattern failed, using setter approach for ClaimDto mapping: {}", e.getMessage());
            return mapToDtoWithSetters(claim);
        }
    }

    private ClaimDto mapToDtoWithSetters(Claim claim) {
        ClaimDto dto = new ClaimDto();
        dto.setId(claim.getId());
        dto.setClaimNumber(claim.getClaimNumber());
        dto.setPolicyId(claim.getPolicy().getId());
        dto.setPolicyNumber(claim.getPolicy().getPolicyNumber());
        dto.setCustomerName(claim.getPolicy().getCustomer().getFullName());
        dto.setDescription(claim.getDescription());
        dto.setClaimAmount(claim.getClaimAmount());
        dto.setIncidentDate(claim.getIncidentDate());
        dto.setStatus(claim.getStatus().name());
        dto.setStatusDescription(claim.getStatus().getDescription());
        dto.setSubmittedDate(claim.getSubmittedDate());
        dto.setProcessedDate(claim.getProcessedDate());
        dto.setRejectionReason(claim.getRejectionReason());
        dto.setApprovedAmount(claim.getApprovedAmount());
        dto.setCreatedAt(claim.getCreatedAt());
        dto.setUpdatedAt(claim.getUpdatedAt());
        dto.setCanBeModified(claim.canBeProcessed());
        dto.setWithinCoverageLimit(claim.isWithinCoverageLimit());
        dto.setDaysSinceSubmission(claim.getDaysSinceSubmission());
        return dto;
    }

    private Claim mapToEntity(ClaimDto dto) {
        try {
            return Claim.builder()
                    .description(dto.getDescription())
                    .claimAmount(dto.getClaimAmount())
                    .incidentDate(dto.getIncidentDate())
                    .status(ClaimStatus.PENDING)
                    .build();
        } catch (Exception e) {
            log.warn("Builder pattern failed, using setter approach for Claim mapping: {}", e.getMessage());
            return mapToEntityWithSetters(dto);
        }
    }

    private Claim mapToEntityWithSetters(ClaimDto dto) {
        Claim claim = new Claim();
        claim.setDescription(dto.getDescription());
        claim.setClaimAmount(dto.getClaimAmount());
        claim.setIncidentDate(dto.getIncidentDate());
        claim.setStatus(ClaimStatus.PENDING);
        return claim;
    }

    // VALIDATION METHODS

    private void validateClaimCreationRequest(ClaimDto claimDto) {
        if (claimDto == null) {
            throw new IllegalArgumentException("Claim data is required");
        }

        if (claimDto.getPolicyId() == null) {
            throw new IllegalArgumentException("Policy ID is required");
        }

        if (claimDto.getDescription() == null || claimDto.getDescription().trim().isEmpty()) {
            throw new IllegalArgumentException("Claim description is required");
        }

        if (claimDto.getClaimAmount() == null || claimDto.getClaimAmount().signum() <= 0) {
            throw new IllegalArgumentException("Claim amount must be greater than zero");
        }

        if (claimDto.getIncidentDate() == null) {
            throw new IllegalArgumentException("Incident date is required");
        }

        if (claimDto.getIncidentDate().isAfter(LocalDateTime.now())) {
            throw new IllegalArgumentException("Incident date cannot be in the future");
        }

        if (claimDto.getIncidentDate().isBefore(LocalDateTime.now().minusDays(MAX_INCIDENT_DAYS_OLD))) {
            throw new BusinessLogicException("Incident date cannot be more than " + MAX_INCIDENT_DAYS_OLD + " days old");
        }
    }

    private void validatePolicyForClaim(Policy policy) {
        if (policy.getStatus() != PolicyStatus.ACTIVE) {
            throw new BusinessLogicException("Claims can only be filed against active policies");
        }

        if (policy.isExpired()) {
            throw new BusinessLogicException("Claims cannot be filed against expired policies");
        }

        if (!policy.canBeClaimed()) {
            throw new BusinessLogicException("This policy is not eligible for claims");
        }
    }

    private void validateClaimBusinessRules(ClaimDto claimDto, Policy policy) {
        // Check claim amount against coverage
        if (claimDto.getClaimAmount().compareTo(policy.getCoverageAmount()) > 0) {
            throw new BusinessLogicException("Claim amount cannot exceed policy coverage amount of $" +
                    policy.getCoverageAmount());
        }

        // Check maximum claims per policy
        long existingClaimsCount = claimRepository.countByPolicyIdAndStatus(policy.getId(), ClaimStatus.APPROVED);
        if (existingClaimsCount >= MAX_CLAIMS_PER_POLICY) {
            throw new BusinessLogicException("Policy has reached the maximum limit of " +
                    MAX_CLAIMS_PER_POLICY + " approved claims");
        }

        // Check for duplicate claim numbers
        if (claimDto.getClaimNumber() != null &&
                claimRepository.existsByClaimNumber(claimDto.getClaimNumber())) {
            throw new BusinessLogicException("Claim number already exists: " + claimDto.getClaimNumber());
        }
    }

    private void validateUserAccessToClaim(Claim claim) {
        User currentUser = getCurrentUser();

        if (currentUser.getRole() == Role.CUSTOMER &&
                !currentUser.getId().equals(claim.getPolicy().getCustomer().getId())) {
            throw new BusinessLogicException("Access denied: You can only view your own claims");
        }
    }

    private void validateUserPermissionForStatusUpdate() {
        User currentUser = getCurrentUser();
        if (currentUser.getRole() == Role.CUSTOMER) {
            throw new BusinessLogicException("Customers cannot update claim status");
        }
    }

    private void validateStatusTransition(ClaimStatus currentStatus, ClaimStatus newStatus) {
        if (currentStatus == newStatus) {
            throw new BusinessLogicException("Claim is already in " + newStatus + " status");
        }

        boolean isValidTransition = switch (currentStatus) {
            case PENDING -> newStatus == ClaimStatus.PROCESSING || newStatus == ClaimStatus.APPROVED ||
                    newStatus == ClaimStatus.REJECTED || newStatus == ClaimStatus.CANCELLED;
            case PROCESSING -> newStatus == ClaimStatus.APPROVED || newStatus == ClaimStatus.REJECTED ||
                    newStatus == ClaimStatus.CANCELLED;
            case APPROVED -> newStatus == ClaimStatus.PAID;
            case REJECTED, CANCELLED, PAID -> false; // Terminal states
        };

        if (!isValidTransition) {
            throw new BusinessLogicException(
                    String.format("Invalid status transition from %s to %s", currentStatus, newStatus));
        }
    }

    private void updateClaimWithNewStatus(Claim claim, ClaimStatus newStatus, ClaimStatusUpdateDto statusUpdate) {
        claim.setStatus(newStatus);

        switch (newStatus) {
            case APPROVED -> {
                if (statusUpdate.getApprovedAmount() != null) {
                    claim.setApprovedAmount(statusUpdate.getApprovedAmount());
                } else {
                    claim.setApprovedAmount(claim.getClaimAmount());
                }
            }
            case REJECTED -> {
                if (statusUpdate.getRejectionReason() != null) {
                    claim.setRejectionReason(statusUpdate.getRejectionReason());
                }
            }
        }
    }

    private void sendStatusUpdateNotification(Claim claim, ClaimStatus oldStatus, ClaimStatus newStatus) {
        try {
            switch (newStatus) {
                case APPROVED -> emailService.sendClaimApprovalEmail(claim);
                case REJECTED -> emailService.sendClaimRejectionEmail(claim, claim.getRejectionReason());
                default -> emailService.sendClaimStatusUpdateEmail(claim);
            }
        } catch (Exception e) {
            log.error("Failed to send notification email for claim: {}", claim.getClaimNumber(), e);
        }
    }

    // SPECIFICATION METHODS

    private Specification<Claim> createBaseSpecification() {
        return (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();
    }

    private Specification<Claim> createClaimNumberSpecification(String claimNumber) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.like(criteriaBuilder.lower(root.get("claimNumber")),
                        "%" + claimNumber.toLowerCase() + "%");
    }

    private Specification<Claim> createStatusSpecification(String status) {
        return (root, query, criteriaBuilder) -> {
            try {
                ClaimStatus enumStatus = ClaimStatus.valueOf(status.toUpperCase());
                return criteriaBuilder.equal(root.get("status"), enumStatus);
            } catch (IllegalArgumentException e) {
                log.warn("Invalid claim status provided: {}", status);
                return criteriaBuilder.disjunction();
            }
        };
    }

    private Specification<Claim> createPolicyIdSpecification(Long policyId) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.equal(root.get("policy").get("id"), policyId);
    }

    private Specification<Claim> createRoleBasedSpecification() {
        User currentUser = getCurrentUser();

        if (currentUser.getRole() == Role.CUSTOMER) {
            return (root, query, criteriaBuilder) ->
                    criteriaBuilder.equal(root.get("policy").get("customer").get("id"), currentUser.getId());
        }

        return (root, query, criteriaBuilder) -> criteriaBuilder.conjunction();
    }

    // UTILITY METHODS

    private boolean hasAccessToClaim(Claim claim) {
        try {
            validateUserAccessToClaim(claim);
            return true;
        } catch (BusinessLogicException e) {
            return false;
        }
    }

    private String generateClaimNumber() {
        return "CLM-" + LocalDateTime.now().getYear() + "-" +
                UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }

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
