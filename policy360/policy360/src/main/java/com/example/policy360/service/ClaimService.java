package com.example.policy360.service;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.entity.enums.ClaimStatus;

import java.util.List;

public interface ClaimService {
    ClaimDto createClaim(ClaimDto claimDto);
    ClaimDto updateClaimStatus(Long claimId, ClaimStatus status);
    ClaimDto getClaimById(Long id);
    List<ClaimDto> getAllClaims();
    List<ClaimDto> getClaimsByPolicyId(Long policyId);
    List<ClaimDto> getClaimsByStatus(ClaimStatus status);
    void deleteClaim(Long id);
}
