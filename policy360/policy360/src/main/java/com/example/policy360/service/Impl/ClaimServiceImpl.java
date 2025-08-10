package com.example.policy360.service.Impl;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.entity.Claim;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.exception.BusinessLogicException;
import com.example.policy360.exception.ClaimNotFoundException;
import com.example.policy360.exception.PolicyNotFoundException;
import com.example.policy360.repository.ClaimRepository;
import com.example.policy360.repository.PolicyRepository;
import com.example.policy360.service.ClaimService;
import com.example.policy360.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
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
    private final EmailService emailService;

    @Override
    public ClaimDto createClaim(ClaimDto claimDto) {
        log.info("Creating claim for policy ID: {}", claimDto.getPolicyId());

        Policy policy = policyRepository.findById(claimDto.getPolicyId())
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + claimDto.getPolicyId()));

        validateClaimCreation(claimDto, policy);

        Claim claim = new Claim();
        claim.setClaimNumber("CLM-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        claim.setPolicy(policy);
        claim.setDescription(claimDto.getDescription());
        claim.setClaimAmount(claimDto.getClaimAmount());
        claim.setIncidentDate(claimDto.getIncidentDate());
        claim.setStatus(ClaimStatus.PENDING);
        claim.setSubmittedDate(LocalDateTime.now());
        claim.setCreatedAt(LocalDateTime.now());
        claim.setUpdatedAt(LocalDateTime.now());

        Claim savedClaim = claimRepository.save(claim);
        log.info("Claim created successfully with ID: {} and number: {}", savedClaim.getId(), savedClaim.getClaimNumber());

        return convertToDto(savedClaim);
    }

    @Override
    public ClaimDto updateClaimStatus(Long claimId, ClaimStatus status) {
        log.info("Updating claim status for claim ID: {} to status: {}", claimId, status);

        Claim claim = claimRepository.findById(claimId)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + claimId));

        validateStatusTransition(claim.getStatus(), status);

        claim.setStatus(status);
        claim.setProcessedDate(LocalDateTime.now());
        claim.setUpdatedAt(LocalDateTime.now());

        Claim updatedClaim = claimRepository.save(claim);

        try {
            emailService.sendClaimStatusUpdateEmail(updatedClaim);
        } catch (Exception e) {
            log.warn("Failed to send status update email for claim: {}", updatedClaim.getClaimNumber(), e);
        }

        log.info("Claim status updated successfully for claim ID: {}", claimId);

        return convertToDto(updatedClaim);
    }

    @Override
    public ClaimDto getClaimById(Long id) {
        log.info("Fetching claim with ID: {}", id);

        Claim claim = claimRepository.findById(id)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + id));

        return convertToDto(claim);
    }

    @Override
    public List<ClaimDto> getAllClaims() {
        log.info("Fetching all claims");

        List<Claim> claims = claimRepository.findAll();
        return claims.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    @Override
    public List<ClaimDto> getClaimsByPolicyId(Long policyId) {
        log.info("Fetching claims for policy ID: {}", policyId);

        List<Claim> claims = claimRepository.findByPolicyId(policyId);
        return claims.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    @Override
    public List<ClaimDto> getClaimsByStatus(ClaimStatus status) {
        log.info("Fetching claims with status: {}", status);

        List<Claim> claims = claimRepository.findByStatus(status);
        return claims.stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    @Override
    public void deleteClaim(Long id) {
        log.info("Deleting claim with ID: {}", id);

        Claim claim = claimRepository.findById(id)
                .orElseThrow(() -> new ClaimNotFoundException("Claim not found with ID: " + id));

        if (claim.getStatus() != ClaimStatus.PENDING) {
            throw new BusinessLogicException("Cannot delete claim that is not in PENDING status");
        }

        claimRepository.delete(claim);
        log.info("Claim deleted successfully with ID: {}", id);
    }

    private void validateClaimCreation(ClaimDto claimDto, Policy policy) {
        if (policy.getStatus() != com.example.policy360.entity.enums.PolicyStatus.ACTIVE) {
            throw new BusinessLogicException("Cannot create claim for inactive policy");
        }

        if (claimDto.getClaimAmount().compareTo(policy.getCoverageAmount()) > 0) {
            throw new BusinessLogicException("Claim amount cannot exceed policy coverage amount");
        }

        if (claimDto.getIncidentDate().isAfter(LocalDateTime.now())) {
            throw new BusinessLogicException("Incident date cannot be in the future");
        }

        if (claimDto.getIncidentDate().toLocalDate().isBefore(policy.getStartDate())) {
            throw new BusinessLogicException("Incident date cannot be before policy start date");
        }
    }

    private void validateStatusTransition(ClaimStatus currentStatus, ClaimStatus newStatus) {
        if (currentStatus == newStatus) {
            throw new BusinessLogicException("Claim is already in " + newStatus + " status");
        }

        if (currentStatus == ClaimStatus.APPROVED || currentStatus == ClaimStatus.REJECTED) {
            throw new BusinessLogicException("Cannot change status of a finalized claim");
        }
    }

    private ClaimDto convertToDto(Claim claim) {
        ClaimDto dto = new ClaimDto();
        dto.setId(claim.getId());
        dto.setClaimNumber(claim.getClaimNumber());
        dto.setPolicyId(claim.getPolicy().getId());
        dto.setDescription(claim.getDescription());
        dto.setClaimAmount(claim.getClaimAmount());
        dto.setStatus(claim.getStatus().name());
        dto.setIncidentDate(claim.getIncidentDate());
        dto.setSubmittedDate(claim.getSubmittedDate());
        dto.setProcessedDate(claim.getProcessedDate());
        return dto;
    }
}
