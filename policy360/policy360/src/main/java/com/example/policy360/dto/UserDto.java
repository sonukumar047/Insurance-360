package com.example.policy360.dto;

import com.example.policy360.util.DataMaskingUtil;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String mobileNumber;
    private String role;
    private String roleDescription;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean isActive;

    // Masking methods
    public UserDto applyMasking(DataMaskingUtil maskingUtil, String viewerRole) {
        UserDto masked = this.toBuilder().build(); // Create a copy

        if (!maskingUtil.canViewUnmaskedData(viewerRole, "PII")) {
            masked.setEmail(maskingUtil.maskEmail(this.email));
            masked.setFullName(maskingUtil.maskFullName(this.fullName));
            masked.setMobileNumber(maskingUtil.maskPhoneNumber(this.mobileNumber));
        }

        return masked;
    }

    // Builder pattern support for copying
    public UserDtoBuilder toBuilder() {
        return UserDto.builder()
                .id(this.id)
                .username(this.username)
                .email(this.email)
                .fullName(this.fullName)
                .mobileNumber(this.mobileNumber)
                .role(this.role)
                .roleDescription(this.roleDescription)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt)
                .isActive(this.isActive);
    }
}
