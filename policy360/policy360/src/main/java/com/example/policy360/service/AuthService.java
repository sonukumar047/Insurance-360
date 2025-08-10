package com.example.policy360.service;

import com.example.policy360.dto.AuthRequest;
import com.example.policy360.dto.AuthResponse;
import com.example.policy360.dto.RegisterRequest;
import com.example.policy360.dto.RegisterResponse;

public interface AuthService {
    AuthResponse login(AuthRequest authRequest);
    RegisterResponse register(RegisterRequest registerRequest);
}
