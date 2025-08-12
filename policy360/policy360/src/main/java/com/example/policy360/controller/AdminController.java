package com.example.policy360.controller;

import com.example.policy360.dto.UserDto;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.service.Impl.MaskingService;
import com.example.policy360.util.DataMaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserRepository userRepository;
    private final MaskingService maskingService;
    private final DataMaskingUtil dataMaskingUtil;

    @GetMapping("/users")
    public ResponseEntity<Page<UserDto>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String viewerRole = getCurrentUserRole();
        String viewerUsername = getCurrentUsername();

        log.info("Admin {} fetching all users - page: {}, size: {}, sortBy: {}, sortDir: {}, unmask: {}",
                viewerUsername, page, size, sortBy, sortDir, unmask);

        Sort sort = sortDir.equalsIgnoreCase("desc") ?
                Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();

        Pageable pageable = PageRequest.of(page, size, sort);
        Page<User> users = userRepository.findAll(pageable);

        Page<UserDto> userDtos = users.map(this::convertToDto);

        // Apply masking unless explicitly requested to unmask and user has permission
        if (!unmask || !canUnmaskData(viewerRole)) {
            userDtos = maskingService.maskUserDataPage(userDtos, viewerRole);
            log.info("Found {} users (with masking applied)", users.getTotalElements());
        } else {
            log.info("Found {} users (unmasked - admin privilege)", users.getTotalElements());
        }

        return ResponseEntity.ok(userDtos);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserDto> getUserById(
            @PathVariable Long id,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String viewerRole = getCurrentUserRole();
        String viewerUsername = getCurrentUsername();

        log.info("Admin {} fetching user by ID: {} (unmask: {})", viewerUsername, id, unmask);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        UserDto userDto = convertToDto(user);

        // Apply masking unless explicitly requested to unmask and user has permission
        if (!unmask || !canUnmaskData(viewerRole)) {
            boolean isOwnData = user.getUsername().equals(viewerUsername);
            userDto = maskingService.maskUserData(userDto, viewerRole, isOwnData);
            log.info("User {} retrieved with masking applied", id);
        } else {
            log.info("User {} retrieved unmasked (admin privilege)", id);
        }

        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/users/search")
    public ResponseEntity<Page<UserDto>> searchUsers(
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Role role,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String viewerRole = getCurrentUserRole();
        String viewerUsername = getCurrentUsername();

        log.info("Admin {} searching users - query: {}, role: {}, page: {}, size: {}, unmask: {}",
                viewerUsername, query, role, page, size, unmask);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<User> users;

        if (query != null && role != null) {
            users = userRepository.findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCaseOrFullNameContainingIgnoreCaseAndRole(
                    query, query, query, role, pageable);
        } else if (query != null) {
            users = userRepository.findByUsernameContainingIgnoreCaseOrEmailContainingIgnoreCaseOrFullNameContainingIgnoreCase(
                    query, query, query, pageable);
        } else if (role != null) {
            users = userRepository.findByRole(role, pageable);
        } else {
            users = userRepository.findAll(pageable);
        }

        Page<UserDto> userDtos = users.map(this::convertToDto);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            userDtos = maskingService.maskUserDataPage(userDtos, viewerRole);
            log.info("Search returned {} users (with masking)", users.getTotalElements());
        } else {
            log.info("Search returned {} users (unmasked)", users.getTotalElements());
        }

        return ResponseEntity.ok(userDtos);
    }

    @GetMapping("/users/role/{role}")
    public ResponseEntity<Page<UserDto>> getUsersByRole(
            @PathVariable Role role,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "false") boolean unmask) {

        String viewerRole = getCurrentUserRole();
        String viewerUsername = getCurrentUsername();

        log.info("Admin {} fetching users by role: {} (unmask: {})", viewerUsername, role, unmask);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<User> users = userRepository.findByRole(role, pageable);

        Page<UserDto> userDtos = users.map(this::convertToDto);

        // Apply masking
        if (!unmask || !canUnmaskData(viewerRole)) {
            userDtos = maskingService.maskUserDataPage(userDtos, viewerRole);
        }

        log.info("Found {} users with role {} (masking: {})",
                users.getTotalElements(), role, !unmask);

        return ResponseEntity.ok(userDtos);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<UserDto> updateUser(
            @PathVariable Long id,
            @RequestBody UserDto userDto) {

        String viewerUsername = getCurrentUsername();
        log.info("Admin {} updating user: {}", viewerUsername, id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // Log the masking status of incoming data for audit purposes
        String maskingSummary = getUserUpdateMaskingSummary(userDto);
        log.info("User update request masking summary: {}", maskingSummary);

        // Update allowed fields (incoming data might be masked, handle accordingly)
        updateUserFields(user, userDto);

        User savedUser = userRepository.save(user);

        // Return masked response for consistency
        UserDto responseDto = convertToDto(savedUser);
        boolean isOwnData = savedUser.getUsername().equals(viewerUsername);
        UserDto maskedResponse = maskingService.maskUserData(responseDto, getCurrentUserRole(), isOwnData);

        log.info("User {} updated successfully by {}", id, viewerUsername);
        return ResponseEntity.ok(maskedResponse);
    }

    @PatchMapping("/users/{id}/activate")
    public ResponseEntity<String> activateUser(@PathVariable Long id) {
        String viewerUsername = getCurrentUsername();
        log.info("Admin {} activating user: {}", viewerUsername, id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        user.setActive(true);
        userRepository.save(user);

        log.info("User {} activated by admin {}", id, viewerUsername);
        return ResponseEntity.ok("User activated successfully");
    }

    @PatchMapping("/users/{id}/deactivate")
    public ResponseEntity<String> deactivateUser(@PathVariable Long id) {
        String viewerUsername = getCurrentUsername();
        log.info("Admin {} deactivating user: {}", viewerUsername, id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        user.setActive(false);
        userRepository.save(user);

        log.info("User {} deactivated by admin {}", id, viewerUsername);
        return ResponseEntity.ok("User deactivated successfully");
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        String viewerUsername = getCurrentUsername();
        log.info("Admin {} attempting to delete user: {}", viewerUsername, id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // Don't allow deleting admin users
        if (user.getRole() == Role.ADMIN) {
            log.warn("Admin {} attempted to delete admin user {}", viewerUsername, id);
            return ResponseEntity.badRequest().body("Cannot delete admin users");
        }

        // Log the masked user info for audit (before deletion)
        UserDto userDto = convertToDto(user);
        UserDto maskedForAudit = maskingService.maskUserData(userDto, getCurrentUserRole(), false);
        log.info("Deleting user: {} (username: {})", id, maskedForAudit.getUsername());

        userRepository.delete(user);
        log.info("User {} deleted successfully by admin {}", id, viewerUsername);

        return ResponseEntity.ok("User deleted successfully");
    }

    // New endpoint to get masking configuration info
    @GetMapping("/users/masking-info")
    public ResponseEntity<Object> getMaskingInfo() {
        String viewerRole = getCurrentUserRole();

        return ResponseEntity.ok(Map.of(
                "viewerRole", viewerRole,
                "canUnmask", canUnmaskData(viewerRole),
                "maskingEnabled", true, // Could be from configuration
                "supportedMaskingTypes", List.of("EMAIL", "PHONE", "NAME", "FINANCIAL")
        ));
    }

    // Utility methods
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "unknown";
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
        // Only admins can request unmasked data
        return "ADMIN".equals(role);
    }

    private void updateUserFields(User user, UserDto userDto) {
        // Handle potentially masked incoming data
        if (userDto.getFullName() != null && !isMaskedData(userDto.getFullName())) {
            user.setFullName(userDto.getFullName());
        }
        if (userDto.getEmail() != null && !isMaskedData(userDto.getEmail())) {
            user.setEmail(userDto.getEmail());
        }
        if (userDto.getMobileNumber() != null && !isMaskedData(userDto.getMobileNumber())) {
            user.setMobileNumber(userDto.getMobileNumber());
        }

        // Active status is not masked
        user.setActive(userDto.isActive());
    }

    private boolean isMaskedData(String data) {
        // Simple check to see if data contains masking characters
        return data != null && data.contains("*");
    }

    private String getUserUpdateMaskingSummary(UserDto userDto) {
        StringBuilder summary = new StringBuilder();
        summary.append("Fields: ");
        summary.append("email=").append(isMaskedData(userDto.getEmail()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("fullName=").append(isMaskedData(userDto.getFullName()) ? "MASKED" : "CLEAR").append(", ");
        summary.append("mobile=").append(isMaskedData(userDto.getMobileNumber()) ? "MASKED" : "CLEAR");
        return summary.toString();
    }

    // Helper method to convert User to UserDto (unchanged)
    private UserDto convertToDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .mobileNumber(user.getMobileNumber())
                .role(user.getRole().name())
                .roleDescription(user.getRole().getDescription())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .isActive(user.isActive())
                .build();
    }
}
