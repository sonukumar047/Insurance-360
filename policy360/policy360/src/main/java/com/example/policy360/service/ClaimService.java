package com.example.policy360.service;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.dto.ClaimStatusUpdateDto;
import com.example.policy360.entity.enums.ClaimStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

public interface ClaimService {
    ClaimDto createClaim(ClaimDto claimDto);
    ClaimDto getClaimById(Long id);
    ClaimDto getClaimByNumber(String claimNumber);
    Page<ClaimDto> getAllClaims(Pageable pageable);
    List<ClaimDto> getAllClaims();
    ClaimDto updateClaimStatus(Long id, ClaimStatusUpdateDto statusUpdate);
    void deleteClaim(Long id);

    List<ClaimDto> getClaimsByPolicyId(Long policyId);
    List<ClaimDto> getClaimsByCustomerId(Long customerId);
    List<ClaimDto> getClaimsByStatus(ClaimStatus status);
    Page<ClaimDto> getClaimsByStatus(ClaimStatus status, Pageable pageable);

    Page<ClaimDto> searchClaims(String claimNumber, String status, Long policyId, Pageable pageable);
    List<ClaimDto> getPendingClaims();
    List<ClaimDto> getClaimsForReminder(int daysOld);

    BigDecimal getTotalClaimsAmountByPolicy(Long policyId);
    long getClaimsCountByStatus(ClaimStatus status);

    // Business operations
    ClaimDto approveClaim(Long id, BigDecimal approvedAmount);
    ClaimDto rejectClaim(Long id, String reason);
    ClaimDto processClaim(Long id);
}
