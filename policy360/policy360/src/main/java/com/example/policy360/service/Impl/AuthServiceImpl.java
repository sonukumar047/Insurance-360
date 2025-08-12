package com.example.policy360.service.Impl;

import com.example.policy360.dto.*;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.exception.AuthenticationException;
import com.example.policy360.exception.UserAlreadyExistsException;
import com.example.policy360.exception.UserNotFoundException;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.security.JwtTokenUtil;
import com.example.policy360.service.AuthService;
import com.example.policy360.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;
    private final EmailService emailService;

    // In-memory stores (in production, use Redis or database)
    private final ConcurrentHashMap<String, String> passwordResetTokens = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, LocalDateTime> loginAttempts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> activeTokens = new ConcurrentHashMap<>();

    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 30;

    // AUTHENTICATION METHODS

    @Override
    public AuthResponse login(AuthRequest authRequest, String clientIp) {
        log.info("Attempting login for user: {} from IP: {}", authRequest.getUsername(), clientIp);

        try {
            // Check if account is locked
            if (isAccountLocked(authRequest.getUsername())) {
                throw new AuthenticationException("Account is temporarily locked due to multiple failed login attempts");
            }

            // Authenticate user
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()));

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtTokenUtil.generateToken(userDetails);

            User user = userRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new UserNotFoundException("User not found after authentication"));

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            // Clear failed login attempts
            loginAttempts.remove(authRequest.getUsername());

            // Store active token
            activeTokens.put(user.getUsername(), token);

            log.info("Successfully logged in user: {} with role: {} from IP: {}",
                    authRequest.getUsername(), user.getRole(), clientIp);

            return AuthResponse.builder()
                    .token(token)
                    .type("Bearer")
                    .username(user.getUsername())
                    .role(user.getRole().name())
                    .roleDescription(user.getRole().getDescription())
                    .expiresIn(jwtTokenUtil.getExpirationTimeFromToken(token))
                    .message("Login successful")
                    .build();

        } catch (BadCredentialsException e) {
            handleFailedLogin(authRequest.getUsername(), clientIp);
            log.error("Invalid credentials for user: {} from IP: {}", authRequest.getUsername(), clientIp);
            throw new AuthenticationException("Invalid username or password");
        } catch (Exception e) {
            log.error("Login failed for user: {} from IP: {}", authRequest.getUsername(), clientIp, e);
            throw new AuthenticationException("Authentication failed");
        }
    }

    @Override
    public void logout(String username, String clientIp) {
        log.info("User {} logging out from IP: {}", username, clientIp);
        activeTokens.remove(username);
        log.info("User {} logged out successfully from IP: {}", username, clientIp);
    }

    @Override
    public AuthResponse refreshToken(String username, String clientIp) {
        log.info("Token refresh requested for user: {} from IP: {}", username, clientIp);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities("ROLE_" + user.getRole().name())
                .build();

        String newToken = jwtTokenUtil.generateToken(userDetails);
        activeTokens.put(username, newToken);

        log.info("Token refreshed for user: {} from IP: {}", username, clientIp);

        return AuthResponse.builder()
                .token(newToken)
                .type("Bearer")
                .username(user.getUsername())
                .role(user.getRole().name())
                .roleDescription(user.getRole().getDescription())
                .expiresIn(jwtTokenUtil.getExpirationTimeFromToken(newToken))
                .message("Token refreshed successfully")
                .build();
    }

    // REGISTRATION METHODS

    @Override
    public RegisterResponse register(RegisterRequest registerRequest, String clientIp) {
        log.info("Admin registration attempt for user: {} with role: {} from IP: {}",
                registerRequest.getUsername(), registerRequest.getRole(), clientIp);

        validateRegistrationRequest(registerRequest);

        User user = createUser(registerRequest, registerRequest.getRole());
        User savedUser = userRepository.save(user);

        sendWelcomeEmail(savedUser);

        log.info("Successfully registered user: {} with role: {} and ID: {} from IP: {}",
                savedUser.getUsername(), savedUser.getRole(), savedUser.getId(), clientIp);

        return buildRegisterResponse(savedUser, "User registered successfully by admin");
    }

    @Override
    public RegisterResponse registerPublic(PublicRegisterRequest publicRegisterRequest, String clientIp) {
        log.info("Public registration attempt for user: {} from IP: {}",
                publicRegisterRequest.getUsername(), clientIp);

        validatePublicRegistrationRequest(publicRegisterRequest);

        RegisterRequest registerRequest = new RegisterRequest();
        registerRequest.setUsername(publicRegisterRequest.getUsername());
        registerRequest.setEmail(publicRegisterRequest.getEmail());
        registerRequest.setFullName(publicRegisterRequest.getFullName());
        registerRequest.setMobileNumber(publicRegisterRequest.getMobileNumber());
        registerRequest.setPassword(publicRegisterRequest.getPassword());
        registerRequest.setRole(Role.CUSTOMER); // Auto-assign CUSTOMER role

        User user = createUser(registerRequest, Role.CUSTOMER);
        User savedUser = userRepository.save(user);

        sendWelcomeEmail(savedUser);

        log.info("Successfully registered public user: {} as CUSTOMER with ID: {} from IP: {}",
                savedUser.getUsername(), savedUser.getId(), clientIp);

        return buildRegisterResponse(savedUser, "Customer registration successful");
    }

    @Override
    public RegisterResponse registerAgent(RegisterRequest registerRequest, String clientIp) {
        log.info("Agent registration attempt for user: {} from IP: {}",
                registerRequest.getUsername(), clientIp);

        validateRegistrationRequest(registerRequest);
        registerRequest.setRole(Role.AGENT); // Force AGENT role

        User user = createUser(registerRequest, Role.AGENT);
        User savedUser = userRepository.save(user);

        sendWelcomeEmail(savedUser);

        log.info("Successfully registered agent: {} with ID: {} from IP: {}",
                savedUser.getUsername(), savedUser.getId(), clientIp);

        return buildRegisterResponse(savedUser, "Agent registration successful");
    }

    @Override
    public RegisterResponse registerCustomer(RegisterRequest registerRequest, String clientIp) {
        log.info("Customer registration attempt for user: {} from IP: {}",
                registerRequest.getUsername(), clientIp);

        validateRegistrationRequest(registerRequest);
        registerRequest.setRole(Role.CUSTOMER); // Force CUSTOMER role

        User user = createUser(registerRequest, Role.CUSTOMER);
        User savedUser = userRepository.save(user);

        sendWelcomeEmail(savedUser);

        log.info("Successfully registered customer: {} with ID: {} from IP: {}",
                savedUser.getUsername(), savedUser.getId(), clientIp);

        return buildRegisterResponse(savedUser, "Customer registration successful");
    }

    // PASSWORD MANAGEMENT METHODS

    @Override
    public void requestPasswordReset(String email, String clientIp) {
        log.info("Password reset requested for email: {} from IP: {}", email, clientIp);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("No account found with email: " + email));

        String resetToken = UUID.randomUUID().toString();
        passwordResetTokens.put(resetToken, user.getUsername());

        try {
            emailService.sendPasswordResetEmail(email, resetToken);
            log.info("Password reset email sent for user: {} from IP: {}", user.getUsername(), clientIp);
        } catch (Exception e) {
            log.error("Failed to send password reset email for user: {} from IP: {}", user.getUsername(), clientIp, e);
            throw new RuntimeException("Failed to send password reset email");
        }
    }

    @Override
    public void resetPassword(String token, String newPassword, String clientIp) {
        log.info("Password reset attempt with token from IP: {}", clientIp);

        String username = passwordResetTokens.get(token);
        if (username == null) {
            throw new AuthenticationException("Invalid or expired password reset token");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        // Remove used token
        passwordResetTokens.remove(token);

        log.info("Password reset successfully for user: {} from IP: {}", username, clientIp);
    }

    @Override
    public void changePassword(String username, String currentPassword, String newPassword, String clientIp) {
        log.info("Password change attempt for user: {} from IP: {}", username, clientIp);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate active token to force re-login
        activeTokens.remove(username);

        log.info("Password changed successfully for user: {} from IP: {}", username, clientIp);
    }

    // USER MANAGEMENT METHODS

    @Override
    @Transactional(readOnly = true)
    public UserDto getCurrentUserInfo(String username) {
        log.info("Fetching current user info for: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

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

    @Override
    public UserDto updateUserProfile(String username, UserDto userDto) {
        log.info("Updating profile for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        // Update allowed fields
        if (userDto.getFullName() != null) {
            user.setFullName(userDto.getFullName());
        }
        if (userDto.getEmail() != null) {
            user.setEmail(userDto.getEmail());
        }
        if (userDto.getMobileNumber() != null) {
            user.setMobileNumber(userDto.getMobileNumber());
        }

        user.setUpdatedAt(LocalDateTime.now());
        User updatedUser = userRepository.save(user);

        log.info("Profile updated successfully for user: {}", username);

        return getCurrentUserInfo(username);
    }

    // ACCOUNT MANAGEMENT METHODS

    @Override
    public void lockAccount(String username, String reason) {
        log.info("Locking account for user: {} - Reason: {}", username, reason);
        loginAttempts.put(username, LocalDateTime.now().plusMinutes(LOCKOUT_DURATION_MINUTES));
    }

    @Override
    public void unlockAccount(String username) {
        log.info("Unlocking account for user: {}", username);
        loginAttempts.remove(username);
    }

    @Override
    public boolean isAccountLocked(String username) {
        LocalDateTime lockoutTime = loginAttempts.get(username);
        if (lockoutTime != null) {
            if (LocalDateTime.now().isAfter(lockoutTime)) {
                loginAttempts.remove(username);
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public void activateAccount(String username) {
        log.info("Activating account for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setActive(true);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        log.info("Account activated for user: {}", username);
    }

    @Override
    public void deactivateAccount(String username, String reason) {
        log.info("Deactivating account for user: {} - Reason: {}", username, reason);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        user.setActive(false);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        // Remove active token
        activeTokens.remove(username);

        log.info("Account deactivated for user: {}", username);
    }

    // ROLE-BASED ACCESS METHODS

    @Override
    public boolean hasPermission(String username, String permission) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        return switch (user.getRole()) {
            case ADMIN -> true; // Admin has all permissions
            case AGENT -> isAgentPermission(permission);
            case CUSTOMER -> isCustomerPermission(permission);
        };
    }

    @Override
    public boolean canAccessResource(String username, String resource) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        return switch (user.getRole()) {
            case ADMIN -> true; // Admin can access all resources
            case AGENT -> canAgentAccessResource(resource);
            case CUSTOMER -> canCustomerAccessResource(resource);
        };
    }

    // PRIVATE HELPER METHODS

    private void validateRegistrationRequest(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }
    }

    private void validatePublicRegistrationRequest(PublicRegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + request.getUsername());
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists: " + request.getEmail());
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Password and confirm password do not match");
        }
    }

    private User createUser(RegisterRequest request, Role role) {
        return User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .fullName(request.getFullName())
                .mobileNumber(request.getMobileNumber())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
    }

    private RegisterResponse buildRegisterResponse(User user, String message) {
        return RegisterResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .mobileNumber(user.getMobileNumber())
                .role(user.getRole())
                .roleDescription(user.getRole().getDescription())
                .createdAt(user.getCreatedAt())
                .isActive(user.isActive())
                .message(message)
                .build();
    }

    private void sendWelcomeEmail(User user) {
        try {
            emailService.sendWelcomeEmail(user.getEmail(), user.getUsername());
        } catch (Exception e) {
            log.error("Failed to send welcome email for user: {}", user.getUsername(), e);
        }
    }

    private void handleFailedLogin(String username, String clientIp) {
        String key = username + "_" + clientIp;
        lockAccount(username, "Multiple failed login attempts from " + clientIp);
    }

    private boolean isAgentPermission(String permission) {
        return switch (permission) {
            case "READ_POLICY", "CREATE_POLICY", "UPDATE_POLICY", "READ_CLAIM", "PROCESS_CLAIM" -> true;
            default -> false;
        };
    }

    private boolean isCustomerPermission(String permission) {
        return switch (permission) {
            case "READ_OWN_POLICY", "CREATE_CLAIM", "READ_OWN_CLAIM" -> true;
            default -> false;
        };
    }

    private boolean canAgentAccessResource(String resource) {
        return switch (resource) {
            case "policies", "claims", "dashboard" -> true;
            default -> false;
        };
    }

    private boolean canCustomerAccessResource(String resource) {
        return switch (resource) {
            case "my-policies", "my-claims", "profile" -> true;
            default -> false;
        };
    }
}
