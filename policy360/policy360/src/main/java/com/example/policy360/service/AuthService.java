package com.example.policy360.service;

import com.example.policy360.dto.*;

public interface AuthService {
    // Authentication
    AuthResponse login(AuthRequest authRequest, String clientIp);
    void logout(String username, String clientIp);
    AuthResponse refreshToken(String username, String clientIp);

    // Registration
    RegisterResponse register(RegisterRequest registerRequest, String clientIp);
    RegisterResponse registerPublic(PublicRegisterRequest publicRegisterRequest, String clientIp);
    RegisterResponse registerAgent(RegisterRequest registerRequest, String clientIp);
    RegisterResponse registerCustomer(RegisterRequest registerRequest, String clientIp);

    // Password Management
    void requestPasswordReset(String email, String clientIp);
    void resetPassword(String token, String newPassword, String clientIp);
    void changePassword(String username, String currentPassword, String newPassword, String clientIp);

    // User Management
    UserDto getCurrentUserInfo(String username);
    UserDto updateUserProfile(String username, UserDto userDto);

    // Account Management
    void lockAccount(String username, String reason);
    void unlockAccount(String username);
    boolean isAccountLocked(String username);
    void activateAccount(String username);
    void deactivateAccount(String username, String reason);

    // Role-based operations
    boolean hasPermission(String username, String permission);
    boolean canAccessResource(String username, String resource);
}
