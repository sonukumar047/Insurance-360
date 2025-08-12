package com.example.policy360.service.Impl;

import com.example.policy360.config.MaskingConfig;
import com.example.policy360.dto.PolicyStatisticsDto;
import com.example.policy360.dto.UserDto;
import com.example.policy360.dto.PolicyDto;
import com.example.policy360.dto.ClaimDto;
import com.example.policy360.util.DataMaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MaskingService {

    private final DataMaskingUtil dataMaskingUtil;
    private final MaskingConfig maskingConfig;

    /**
     * Apply masking to a single UserDto based on viewer's role
     */
    public UserDto maskUserData(UserDto userDto, String viewerRole, boolean isOwnData) {
        if (!maskingConfig.isEnabled()) {
            return userDto;
        }

        // Don't mask if admin and admin is exempt
        if (maskingConfig.isAdminExempt() && "ADMIN".equals(viewerRole)) {
            return userDto;
        }

        // Don't mask own data for customers
        if (isOwnData && "CUSTOMER".equals(viewerRole)) {
            return userDto;
        }

        return userDto.applyMasking(dataMaskingUtil, viewerRole);
    }

    /**
     * Apply masking to a list of UserDto objects
     */
    public List<UserDto> maskUserDataList(List<UserDto> userDtos, String viewerRole) {
        return userDtos.stream()
                .map(userDto -> maskUserData(userDto, viewerRole, false))
                .collect(Collectors.toList());
    }

    /**
     * Apply masking to a paginated list of UserDto objects
     */
    public Page<UserDto> maskUserDataPage(Page<UserDto> userDtoPage, String viewerRole) {
        List<UserDto> maskedContent = maskUserDataList(userDtoPage.getContent(), viewerRole);
        return new PageImpl<>(maskedContent, userDtoPage.getPageable(), userDtoPage.getTotalElements());
    }

    /**
     * Determine if masking should be applied based on context
     */
    public boolean shouldApplyMasking(String viewerRole, String dataOwnerRole, boolean isOwnData) {
        if (!maskingConfig.isEnabled()) {
            return false;
        }

        // Admin exemption
        if (maskingConfig.isAdminExempt() && "ADMIN".equals(viewerRole)) {
            return false;
        }

        // Own data exemption for customers
        if (isOwnData && "CUSTOMER".equals(viewerRole)) {
            return false;
        }

        return true;
    }

    // Add these methods to your MaskingService

    public ClaimDto maskClaimData(ClaimDto claimDto, String viewerRole, boolean isOwnClaim) {
        if (!maskingConfig.isEnabled()) {
            return claimDto;
        }

        if (maskingConfig.isAdminExempt() && "ADMIN".equals(viewerRole)) {
            return claimDto;
        }

        // Customer viewing own claim gets less masking
        if (isOwnClaim && "CUSTOMER".equals(viewerRole)) {
            return applyPartialClaimMasking(claimDto);
        }

        return claimDto.applyMasking(dataMaskingUtil, viewerRole, isOwnClaim);
    }

    public List<ClaimDto> maskClaimDataList(List<ClaimDto> claimDtos, String viewerRole, String viewerUsername) {
        return claimDtos.stream()
                .map(claimDto -> {
                    boolean isOwnClaim = "CUSTOMER".equals(viewerRole) &&
                            claimDto.getCustomerUsername() != null &&
                            claimDto.getCustomerUsername().equals(viewerUsername);
                    return maskClaimData(claimDto, viewerRole, isOwnClaim);
                })
                .collect(Collectors.toList());
    }

    public Page<ClaimDto> maskClaimDataPage(Page<ClaimDto> claimDtoPage, String viewerRole) {
        List<ClaimDto> maskedContent = claimDtoPage.getContent().stream()
                .map(claimDto -> maskClaimData(claimDto, viewerRole, false))
                .collect(Collectors.toList());
        return new PageImpl<>(maskedContent, claimDtoPage.getPageable(), claimDtoPage.getTotalElements());
    }

    private ClaimDto applyPartialClaimMasking(ClaimDto claimDto) {
        // Apply minimal masking for customers viewing their own claims
        ClaimDto masked = claimDto.toBuilder().build();
        // Only mask very sensitive details if needed
        return masked;
    }

    // Add these methods to your MaskingService

    public PolicyDto maskPolicyData(PolicyDto policyDto, String viewerRole, boolean isOwnPolicy) {
        if (!maskingConfig.isEnabled()) {
            return policyDto;
        }

        if (maskingConfig.isAdminExempt() && "ADMIN".equals(viewerRole)) {
            return policyDto;
        }

        // Customer viewing own policy gets less masking
        if (isOwnPolicy && "CUSTOMER".equals(viewerRole)) {
            return applyPartialPolicyMasking(policyDto);
        }

        return policyDto.applyMasking(dataMaskingUtil, viewerRole, isOwnPolicy);
    }

    public List<PolicyDto> maskPolicyDataList(List<PolicyDto> policyDtos, String viewerRole, String viewerUsername) {
        return policyDtos.stream()
                .map(policyDto -> {
                    boolean isOwnPolicy = "CUSTOMER".equals(viewerRole) &&
                            policyDto.getCustomerUsername() != null &&
                            policyDto.getCustomerUsername().equals(viewerUsername);
                    return maskPolicyData(policyDto, viewerRole, isOwnPolicy);
                })
                .collect(Collectors.toList());
    }

    public Page<PolicyDto> maskPolicyDataPage(Page<PolicyDto> policyDtoPage, String viewerRole) {
        List<PolicyDto> maskedContent = policyDtoPage.getContent().stream()
                .map(policyDto -> maskPolicyData(policyDto, viewerRole, false))
                .collect(Collectors.toList());
        return new PageImpl<>(maskedContent, policyDtoPage.getPageable(), policyDtoPage.getTotalElements());
    }

    public Page<PolicyDto> maskPolicyDataPage(Page<PolicyDto> policyDtoPage, String viewerRole, String viewerUsername) {
        List<PolicyDto> maskedContent = maskPolicyDataList(policyDtoPage.getContent(), viewerRole, viewerUsername);
        return new PageImpl<>(maskedContent, policyDtoPage.getPageable(), policyDtoPage.getTotalElements());
    }

    public PolicyStatisticsDto maskPolicyStatistics(PolicyStatisticsDto statistics, String viewerRole) {
        if ("ADMIN".equals(viewerRole)) {
            return statistics; // Admin sees all statistics
        }

        // Apply masking to sensitive statistical data for agents
        // Implementation depends on your PolicyStatisticsDto structure
        return statistics;
    }

    private PolicyDto applyPartialPolicyMasking(PolicyDto policyDto) {
        // Apply minimal masking for customers viewing their own policies
        PolicyDto masked = policyDto.toBuilder().build();
        // Only mask very sensitive details if needed
        if (masked.getBeneficiaryName() != null) {
            masked.setBeneficiaryName(dataMaskingUtil.maskFullName(masked.getBeneficiaryName()));
        }
        return masked;
    }


}
