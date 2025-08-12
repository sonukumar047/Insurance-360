package com.example.policy360.controller;

import com.example.policy360.dto.*;
import com.example.policy360.service.AuthService;
import com.example.policy360.service.Impl.MaskingService;
import com.example.policy360.util.DataMaskingUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final MaskingService maskingService;
    private final DataMaskingUtil dataMaskingUtil;

    // PUBLIC ENDPOINTS (No authentication required)

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest authRequest,
                                              HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        log.info("Login attempt from IP: {} for user: {}", clientIp,
                dataMaskingUtil.maskSensitiveData(authRequest.getUsername(), 3));

        AuthResponse response = authService.login(authRequest, clientIp);

        // Apply masking to login response (mask sensitive info but keep functional data)
        AuthResponse maskedResponse = applyAuthResponseMasking(response);

        log.info("Login successful for user: {} with role: {}",
                dataMaskingUtil.maskSensitiveData(response.getUsername(), 3), response.getRole());

        return ResponseEntity.ok(maskedResponse);
    }

    @PostMapping("/register-public")
    public ResponseEntity<RegisterResponse> registerPublic(@Valid @RequestBody PublicRegisterRequest publicRegisterRequest,
                                                           HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        log.info("Public registration request from IP: {} for email: {}",
                clientIp, dataMaskingUtil.maskEmail(publicRegisterRequest.getEmail()));

        // Log masked registration data for audit
        String maskingSummary = getRegistrationMaskingSummary(publicRegisterRequest);
        log.info("Registration request masking summary: {}", maskingSummary);

        RegisterResponse response = authService.registerPublic(publicRegisterRequest, clientIp);

        // Apply masking to registration response
        RegisterResponse maskedResponse = applyRegisterResponseMasking(response);

        return ResponseEntity.status(HttpStatus.CREATED).body(maskedResponse);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email,
                                                 HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        log.info("Password reset request for email: {} from IP: {}",
                dataMaskingUtil.maskEmail(email), clientIp);

        authService.requestPasswordReset(email, clientIp);
        return ResponseEntity.ok("Password reset instructions sent to your email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam String token,
                                                @RequestParam String newPassword,
                                                HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        log.info("Password reset attempt from IP: {} with token: {}",
                clientIp, dataMaskingUtil.maskSensitiveData(token, 8));

        authService.resetPassword(token, newPassword, clientIp);
        return ResponseEntity.ok("Password reset successfully");
    }

    // AUTHENTICATED ENDPOINTS

    @PostMapping("/logout")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        log.info("Logout request from user: {} (role: {}) IP: {}",
                dataMaskingUtil.maskSensitiveData(username, 3), viewerRole, clientIp);

        authService.logout(username, clientIp);
        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/refresh")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<AuthResponse> refreshToken(HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        log.info("Token refresh request from user: {} (role: {}) IP: {}",
                dataMaskingUtil.maskSensitiveData(username, 3), viewerRole, clientIp);

        AuthResponse response = authService.refreshToken(username, clientIp);

        // Apply masking to refresh response
        AuthResponse maskedResponse = applyAuthResponseMasking(response);

        return ResponseEntity.ok(maskedResponse);
    }

    @GetMapping("/me")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<UserDto> getCurrentUser(
            @RequestParam(defaultValue = "false") boolean unmask) {

        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        log.info("User {} (role: {}) requesting own profile info (unmask: {})",
                dataMaskingUtil.maskSensitiveData(username, 3), viewerRole, unmask);

        UserDto userDto = authService.getCurrentUserInfo(username);

        // Apply masking - user viewing own data gets minimal masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            userDto = maskingService.maskUserData(userDto, viewerRole, true); // isOwnData = true
            log.info("Profile info retrieved with self-masking applied");
        } else {
            log.info("Profile info retrieved unmasked (admin privilege)");
        }

        return ResponseEntity.ok(userDto);
    }

    @PutMapping("/profile")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<UserDto> updateProfile(@Valid @RequestBody UserDto userDto) {
        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        // Log masking status of incoming data for audit
        String maskingSummary = getUserUpdateMaskingSummary(userDto);
        log.info("Profile update request from user: {} - masking summary: {}",
                dataMaskingUtil.maskSensitiveData(username, 3), maskingSummary);

        UserDto updatedUser = authService.updateUserProfile(username, userDto);

        // Apply masking to response - user updating own profile gets minimal masking
        UserDto maskedResponse = maskingService.maskUserData(updatedUser, viewerRole, true);

        log.info("Profile updated successfully for user: {}",
                dataMaskingUtil.maskSensitiveData(username, 3));

        return ResponseEntity.ok(maskedResponse);
    }

    @PostMapping("/change-password")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT') or hasRole('CUSTOMER')")
    public ResponseEntity<String> changePassword(@RequestParam String currentPassword,
                                                 @RequestParam String newPassword,
                                                 HttpServletRequest request) {
        String clientIp = getClientIpAddress(request);
        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        log.info("Password change request from user: {} (role: {}) IP: {}",
                dataMaskingUtil.maskSensitiveData(username, 3), viewerRole, clientIp);

        authService.changePassword(username, currentPassword, newPassword, clientIp);

        log.info("Password changed successfully for user: {}",
                dataMaskingUtil.maskSensitiveData(username, 3));

        return ResponseEntity.ok("Password changed successfully");
    }

    // ADMIN ONLY ENDPOINTS

    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest registerRequest,
                                                     HttpServletRequest request,
                                                     @RequestParam(defaultValue = "false") boolean unmask) {
        String clientIp = getClientIpAddress(request);
        String adminUsername = getCurrentUsername();

        log.info("Admin {} registration request from IP: {} for user: {}",
                dataMaskingUtil.maskSensitiveData(adminUsername, 3),
                clientIp,
                dataMaskingUtil.maskSensitiveData(registerRequest.getUsername(), 3));

        RegisterResponse response = authService.register(registerRequest, clientIp);

        // Apply masking to response
        if (!unmask) {
            response = applyRegisterResponseMasking(response);
            log.info("Registration response sent with masking applied");
        } else {
            log.info("Registration response sent unmasked (admin privilege)");
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/register-agent")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<RegisterResponse> registerAgent(@Valid @RequestBody RegisterRequest registerRequest,
                                                          HttpServletRequest request,
                                                          @RequestParam(defaultValue = "false") boolean unmask) {
        String clientIp = getClientIpAddress(request);
        String adminUsername = getCurrentUsername();

        log.info("Admin {} agent registration request from IP: {} for user: {}",
                dataMaskingUtil.maskSensitiveData(adminUsername, 3),
                clientIp,
                dataMaskingUtil.maskSensitiveData(registerRequest.getUsername(), 3));

        RegisterResponse response = authService.registerAgent(registerRequest, clientIp);

        // Apply masking to response
        if (!unmask) {
            response = applyRegisterResponseMasking(response);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/register-customer")
    @PreAuthorize("hasRole('ADMIN') or hasRole('AGENT')")
    public ResponseEntity<RegisterResponse> registerCustomer(@Valid @RequestBody RegisterRequest registerRequest,
                                                             HttpServletRequest request,
                                                             @RequestParam(defaultValue = "false") boolean unmask) {
        String clientIp = getClientIpAddress(request);
        String username = getCurrentUsername();
        String viewerRole = getCurrentUserRole();

        log.info("User {} (role: {}) customer registration request from IP: {} for user: {}",
                dataMaskingUtil.maskSensitiveData(username, 3),
                viewerRole,
                clientIp,
                dataMaskingUtil.maskSensitiveData(registerRequest.getUsername(), 3));

        RegisterResponse response = authService.registerCustomer(registerRequest, clientIp);

        // Apply masking based on role
        if (!unmask || !"ADMIN".equals(viewerRole)) {
            response = applyRegisterResponseMasking(response);
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/activate/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> activateAccount(@PathVariable String username) {
        String adminUsername = getCurrentUsername();

        log.info("Admin {} activating account for user: {}",
                dataMaskingUtil.maskSensitiveData(adminUsername, 3),
                dataMaskingUtil.maskSensitiveData(username, 3));

        authService.activateAccount(username);

        return ResponseEntity.ok("Account activated successfully");
    }

    @PostMapping("/deactivate/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deactivateAccount(@PathVariable String username,
                                                    @RequestParam String reason) {
        String adminUsername = getCurrentUsername();

        log.info("Admin {} deactivating account for user: {} - reason: {}",
                dataMaskingUtil.maskSensitiveData(adminUsername, 3),
                dataMaskingUtil.maskSensitiveData(username, 3),
                dataMaskingUtil.maskSensitiveData(reason, 10));

        authService.deactivateAccount(username, reason);

        return ResponseEntity.ok("Account deactivated successfully");
    }

    @PostMapping("/unlock/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> unlockAccount(@PathVariable String username) {
        String adminUsername = getCurrentUsername();

        log.info("Admin {} unlocking account for user: {}",
                dataMaskingUtil.maskSensitiveData(adminUsername, 3),
                dataMaskingUtil.maskSensitiveData(username, 3));

        authService.unlockAccount(username);

        return ResponseEntity.ok("Account unlocked successfully");
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
                "supportedMaskingTypes", List.of("EMAIL", "PHONE", "NAME", "USERNAME", "TOKEN")
        ));
    }

    @GetMapping("/test-masking")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> testMasking() {
        // Test masking functionality for auth data
        String email = "user@example.com";
        String username = "john_doe";
        String token = "abc123def456ghi789";

        return ResponseEntity.ok(Map.of(
                "original", Map.of(
                        "email", email,
                        "username", username,
                        "token", token
                ),
                "masked", Map.of(
                        "email", dataMaskingUtil.maskEmail(email),
                        "username", dataMaskingUtil.maskSensitiveData(username, 3),
                        "token", dataMaskingUtil.maskSensitiveData(token, 8)
                ),
                "viewerRole", getCurrentUserRole()
        ));
    }

    // MASKING HELPER METHODS

    private AuthResponse applyAuthResponseMasking(AuthResponse response) {
        // For AuthResponse, we typically don't mask critical functional data
        // but we can mask sensitive fields if needed
        return AuthResponse.builder()
                .token(response.getToken()) // Keep token unmasked for functionality
                .type(response.getType())
                .username(response.getUsername()) // Keep username unmasked for functionality
                .role(response.getRole())
                .roleDescription(response.getRoleDescription())
                .expiresIn(response.getExpiresIn())
                .build();
    }

    private RegisterResponse applyRegisterResponseMasking(RegisterResponse response) {
        return RegisterResponse.builder()
                .id(response.getId())
                .username(response.getUsername()) // Keep username unmasked for functionality
                .email(dataMaskingUtil.maskEmail(response.getEmail()))
                .fullName(dataMaskingUtil.maskFullName(response.getFullName()))
                .role(response.getRole())
                .isActive(response.isActive())
                .message(response.getMessage())
                .build();
    }

    private String getRegistrationMaskingSummary(PublicRegisterRequest request) {
        StringBuilder summary = new StringBuilder();
        summary.append("Fields: ");
        summary.append("email=").append(isMaskedData(request.getEmail()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("fullName=").append(isMaskedData(request.getFullName()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("mobile=").append(isMaskedData(request.getMobileNumber()) ? "MASKED" : "CLEAR");
        return summary.toString();
    }

    private String getUserUpdateMaskingSummary(UserDto userDto) {
        StringBuilder summary = new StringBuilder();
        summary.append("Fields: ");
        summary.append("email=").append(isMaskedData(userDto.getEmail()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("fullName=").append(isMaskedData(userDto.getFullName()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("mobile=").append(isMaskedData(userDto.getMobileNumber()) ? "MASKED" : "CLEAR");
        return summary.toString();
    }

    private boolean isMaskedData(String data) {
        return data != null && data.contains("*");
    }

    private boolean canUnmaskData(String role) {
        return "ADMIN".equals(role);
    }

    // UTILITY METHODS

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : null;
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

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        return request.getRemoteAddr();
    }
}
