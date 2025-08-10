package com.example.policy360.controller;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.service.ClaimService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/claim")
@RequiredArgsConstructor
public class ClaimController {

    private final ClaimService claimService;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<ClaimDto> createClaim(@Valid @RequestBody ClaimDto claimDto) {
        ClaimDto createdClaim = claimService.createClaim(claimDto);
        return new ResponseEntity<>(createdClaim, HttpStatus.CREATED);
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<ClaimDto> updateClaimStatus(@PathVariable Long id,
                                                      @RequestParam ClaimStatus status) {
        ClaimDto updatedClaim = claimService.updateClaimStatus(id, status);
        return ResponseEntity.ok(updatedClaim);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<ClaimDto> getClaimById(@PathVariable Long id) {
        ClaimDto claim = claimService.getClaimById(id);
        return ResponseEntity.ok(claim);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<ClaimDto>> getAllClaims() {
        List<ClaimDto> claims = claimService.getAllClaims();
        return ResponseEntity.ok(claims);
    }

    @GetMapping("/policy/{policyId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<List<ClaimDto>> getClaimsByPolicyId(@PathVariable Long policyId) {
        List<ClaimDto> claims = claimService.getClaimsByPolicyId(policyId);
        return ResponseEntity.ok(claims);
    }

    @GetMapping("/status/{status}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<ClaimDto>> getClaimsByStatus(@PathVariable ClaimStatus status) {
        List<ClaimDto> claims = claimService.getClaimsByStatus(status);
        return ResponseEntity.ok(claims);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteClaim(@PathVariable Long id) {
        claimService.deleteClaim(id);
        return ResponseEntity.noContent().build();
    }
}
