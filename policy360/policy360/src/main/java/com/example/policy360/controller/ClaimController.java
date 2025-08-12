package com.example.policy360.controller;

import com.example.policy360.dto.ClaimDto;
import com.example.policy360.dto.ClaimStatusUpdateDto;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.service.ClaimService;
import com.example.policy360.service.Impl.MaskingService;
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
@RequestMapping("/claim")
@RequiredArgsConstructor
@Slf4j
public class ClaimController {

    private final ClaimService claimService;
    private final MaskingService maskingService;
    private final DataMaskingUtil dataMaskingUtil;

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<ClaimDto> getClaimById(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claim with ID: {} (unmask: {})",
                currentUser, viewerRole, id, unmask);

        ClaimDto claim = claimService.getClaimById(id);

        // Apply masking based on role and ownership
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(claim, currentUser, viewerRole);
            claim = maskingService.maskClaimData(claim, viewerRole, isOwnClaim);
            log.info("Claim {} retrieved with masking applied (own: {})", id, isOwnClaim);
        } else {
            log.info("Claim {} retrieved unmasked (admin privilege)", id);
        }

        return ResponseEntity.ok(claim);
    }

    @GetMapping("/number/{claimNumber}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<ClaimDto> getClaimByNumber(
            @PathVariable String claimNumber,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claim with number: {} (unmask: {})",
                currentUser, viewerRole, claimNumber, unmask);

        ClaimDto claim = claimService.getClaimByNumber(claimNumber);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(claim, currentUser, viewerRole);
            claim = maskingService.maskClaimData(claim, viewerRole, isOwnClaim);
        }

        return ResponseEntity.ok(claim);
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<ClaimDto>> getAllClaims(
            @PageableDefault(size = 20, sort = "submittedDate") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching all claims with pagination: page={}, size={}, unmask={}",
                currentUser, viewerRole, pageable.getPageNumber(), pageable.getPageSize(), unmask);

        Page<ClaimDto> claims = claimService.getAllClaims(pageable);

        // Apply masking to all claims
        if (!unmask || !canUnmaskData(viewerRole)) {
            claims = maskingService.maskClaimDataPage(claims, viewerRole);
            log.info("Retrieved {} claims with masking applied", claims.getTotalElements());
        } else {
            log.info("Retrieved {} claims unmasked (admin privilege)", claims.getTotalElements());
        }

        return ResponseEntity.ok(claims);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<ClaimDto> createClaim(@Valid @RequestBody ClaimDto claimDto,
                                                HttpServletRequest request) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) creating new claim for policy: {}",
                currentUser, viewerRole, claimDto.getPolicyId());

        // Log masking status of incoming data for audit
        String maskingSummary = getClaimMaskingSummary(claimDto);
        log.info("Claim creation request masking summary: {}", maskingSummary);

        ClaimDto createdClaim = claimService.createClaim(claimDto);

        // Apply masking to response
        boolean isOwnClaim = isViewerOwnClaim(createdClaim, currentUser, viewerRole);
        ClaimDto maskedResponse = maskingService.maskClaimData(createdClaim, viewerRole, isOwnClaim);

        log.info("Claim created successfully with ID: {} and number: {} (masking: {})",
                createdClaim.getId(), createdClaim.getClaimNumber(), !isOwnClaim);
        return new ResponseEntity<>(maskedResponse, HttpStatus.CREATED);
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<ClaimDto> updateClaimStatus(@PathVariable Long id,
                                                      @Valid @RequestBody ClaimStatusUpdateDto statusUpdate,
                                                      HttpServletRequest request,
                                                      @RequestParam(defaultValue = "false") boolean unmask) {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) updating claim status for ID: {} to status: {}",
                currentUser, viewerRole, id, statusUpdate.getStatus());

        ClaimDto updatedClaim = claimService.updateClaimStatus(id, statusUpdate);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(updatedClaim, currentUser, viewerRole);
            updatedClaim = maskingService.maskClaimData(updatedClaim, viewerRole, isOwnClaim);
        }

        log.info("Claim status updated successfully for ID: {}", updatedClaim.getId());
        return ResponseEntity.ok(updatedClaim);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteClaim(@PathVariable Long id, HttpServletRequest request) {
        String currentUser = getCurrentUsername();
        log.info("Admin {} deleting claim with ID: {}", currentUser, id);

        // Log masked claim info for audit before deletion
        ClaimDto claimForAudit = claimService.getClaimById(id);
        ClaimDto maskedForAudit = maskingService.maskClaimData(claimForAudit, "ADMIN", false);
        log.info("Deleting claim: {} (number: {})", id, maskedForAudit.getClaimNumber());

        claimService.deleteClaim(id);

        log.info("Claim deleted successfully with ID: {}", id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/policy/{policyId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<List<ClaimDto>> getClaimsByPolicyId(
            @PathVariable Long policyId,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claims for policy ID: {} (unmask: {})",
                currentUser, viewerRole, policyId, unmask);

        List<ClaimDto> claims = claimService.getClaimsByPolicyId(policyId);

        // Apply masking to list
        if (!unmask || !canUnmaskData(viewerRole)) {
            claims = maskingService.maskClaimDataList(claims, viewerRole, currentUser);
            log.info("Retrieved {} claims for policy {} with masking", claims.size(), policyId);
        } else {
            log.info("Retrieved {} claims for policy {} unmasked", claims.size(), policyId);
        }

        return ResponseEntity.ok(claims);
    }

    @GetMapping("/customer/{customerId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or (hasRole('CUSTOMER') and #customerId == authentication.principal.id)")
    public ResponseEntity<List<ClaimDto>> getClaimsByCustomerId(
            @PathVariable Long customerId,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claims for customer ID: {} (unmask: {})",
                currentUser, viewerRole, customerId, unmask);

        List<ClaimDto> claims = claimService.getClaimsByCustomerId(customerId);

        // Apply masking - customers see their own claims unmasked by default
        if (!unmask || !canUnmaskData(viewerRole)) {
            claims = maskingService.maskClaimDataList(claims, viewerRole, currentUser);
        }

        return ResponseEntity.ok(claims);
    }

    @GetMapping("/status/{status}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<ClaimDto>> getClaimsByStatus(
            @PathVariable String status,
            @PageableDefault(size = 20) Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claims with status: {} (unmask: {})",
                currentUser, viewerRole, status, unmask);

        try {
            ClaimStatus claimStatus = ClaimStatus.valueOf(status.toUpperCase());
            Page<ClaimDto> claims = claimService.getClaimsByStatus(claimStatus, pageable);

            // Apply masking
            if (!unmask || !canUnmaskData(viewerRole)) {
                claims = maskingService.maskClaimDataPage(claims, viewerRole);
            }

            return ResponseEntity.ok(claims);
        } catch (IllegalArgumentException e) {
            log.error("Invalid claim status provided: {}", status);
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<Page<ClaimDto>> searchClaims(
            @RequestParam(required = false) String claimNumber,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Long policyId,
            @PageableDefault(size = 20, sort = "submittedDate") Pageable pageable,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) searching claims with filters - claimNumber: {}, status: {}, policyId: {}, unmask: {}",
                currentUser, viewerRole, claimNumber, status, policyId, unmask);

        Page<ClaimDto> claims = claimService.searchClaims(claimNumber, status, policyId, pageable);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            claims = maskingService.maskClaimDataPage(claims, viewerRole);
            log.info("Search returned {} claims with masking applied", claims.getTotalElements());
        } else {
            log.info("Search returned {} claims unmasked", claims.getTotalElements());
        }

        return ResponseEntity.ok(claims);
    }

    @GetMapping("/pending")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<List<ClaimDto>> getPendingClaims(
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching pending claims (unmask: {})",
                currentUser, viewerRole, unmask);

        List<ClaimDto> pendingClaims = claimService.getPendingClaims();

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            pendingClaims = maskingService.maskClaimDataList(pendingClaims, viewerRole, currentUser);
        }

        return ResponseEntity.ok(pendingClaims);
    }

    @GetMapping("/statuses")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<List<String>> getAvailableStatuses() {
        log.info("Fetching available claim statuses");

        List<String> statuses = Arrays.stream(ClaimStatus.values())
                .map(Enum::name)
                .collect(Collectors.toList());
        return ResponseEntity.ok(statuses);
    }

    // Business operation endpoints with masking

    @PostMapping("/{id}/approve")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<ClaimDto> approveClaim(
            @PathVariable Long id,
            @RequestParam(required = false) BigDecimal approvedAmount,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) approving claim with ID: {} (amount: {})",
                currentUser, viewerRole, id, approvedAmount);

        ClaimDto approvedClaim = claimService.approveClaim(id, approvedAmount);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(approvedClaim, currentUser, viewerRole);
            approvedClaim = maskingService.maskClaimData(approvedClaim, viewerRole, isOwnClaim);
        }

        return ResponseEntity.ok(approvedClaim);
    }

    @PostMapping("/{id}/reject")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<ClaimDto> rejectClaim(
            @PathVariable Long id,
            @RequestParam String reason,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) rejecting claim with ID: {} (reason: {})",
                currentUser, viewerRole, id, reason);

        ClaimDto rejectedClaim = claimService.rejectClaim(id, reason);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(rejectedClaim, currentUser, viewerRole);
            rejectedClaim = maskingService.maskClaimData(rejectedClaim, viewerRole, isOwnClaim);
        }

        return ResponseEntity.ok(rejectedClaim);
    }

    @PostMapping("/{id}/process")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<ClaimDto> processClaim(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) processing claim with ID: {}", currentUser, viewerRole, id);

        ClaimDto processedClaim = claimService.processClaim(id);

        // Apply masking to response
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnClaim = isViewerOwnClaim(processedClaim, currentUser, viewerRole);
            processedClaim = maskingService.maskClaimData(processedClaim, viewerRole, isOwnClaim);
        }

        return ResponseEntity.ok(processedClaim);
    }

    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<?> getClaimStatistics() {
        String currentUser = getCurrentUsername();
        String viewerRole = getCurrentUserRole();
        log.info("User {} (role: {}) fetching claim statistics", currentUser, viewerRole);

        // Implementation can be added based on requirements
        return ResponseEntity.ok().build();
    }

    // New masking utility endpoints

    @GetMapping("/masking-info")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<Map<String, Object>> getMaskingInfo() {
        String viewerRole = getCurrentUserRole();

        return ResponseEntity.ok(Map.of(
                "viewerRole", viewerRole,
                "canUnmask", canUnmaskData(viewerRole),
                "maskingEnabled", true,
                "supportedMaskingTypes", List.of("EMAIL", "PHONE", "NAME", "FINANCIAL", "CLAIM_NUMBER")
        ));
    }

    @GetMapping("/test-masking")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> testMasking() {
        // Test masking functionality
        String email = "customer@example.com";
        String claimNumber = "CLM-2024-001";
        Double amount = 2500.50;

        return ResponseEntity.ok(Map.of(
                "original", Map.of(
                        "email", email,
                        "claimNumber", claimNumber,
                        "amount", amount
                ),
                "masked", Map.of(
                        "email", dataMaskingUtil.maskEmail(email),
                        "claimNumber", dataMaskingUtil.maskClaimNumber(claimNumber),
                        "amount", dataMaskingUtil.maskAmount(amount)
                ),
                "viewerRole", getCurrentUserRole()
        ));
    }

    // Utility methods
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

    private boolean isViewerOwnClaim(ClaimDto claim, String viewerUsername, String viewerRole) {
        if (!"CUSTOMER".equals(viewerRole)) {
            return false; // Only customers have "own" claims
        }

        // Check if the viewer owns this claim
        return claim.getCustomerUsername() != null &&
                claim.getCustomerUsername().equals(viewerUsername);
    }

    private String getClaimMaskingSummary(ClaimDto claimDto) {
        StringBuilder summary = new StringBuilder();
        summary.append("Fields: ");
        summary.append("claimNumber=").append(isMaskedData(claimDto.getClaimNumber()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("description=").append(isMaskedData(claimDto.getDescription()) ? "MASKED" : "CLEAR");
        return summary.toString();
    }

    private boolean isMaskedData(String data) {
        return data != null && data.contains("*");
    }
}
