package com.example.policy360.controller;

import com.example.policy360.dto.AuthRequest;
import com.example.policy360.dto.AuthResponse;
import com.example.policy360.dto.RegisterRequest;
import com.example.policy360.dto.RegisterResponse;
import com.example.policy360.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest authRequest) {
        AuthResponse response = authService.login(authRequest);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @PreAuthorize("hasRole('ADMIN')")  // Only admin can register new users
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest registerRequest) {
        RegisterResponse response = authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/register-public")  // Public registration endpoint (optional)
    public ResponseEntity<RegisterResponse> registerPublic(@Valid @RequestBody RegisterRequest registerRequest) {
        // Force CUSTOMER role for public registration
        registerRequest.setRole(com.example.policy360.entity.enums.Role.CUSTOMER);
        RegisterResponse response = authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
