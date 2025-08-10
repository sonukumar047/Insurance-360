package com.example.policy360.service.Impl;

import com.example.policy360.dto.AuthRequest;
import com.example.policy360.dto.AuthResponse;
import com.example.policy360.dto.RegisterRequest;
import com.example.policy360.dto.RegisterResponse;
import com.example.policy360.entity.User;
import com.example.policy360.exception.UserAlreadyExistsException;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.security.JwtTokenUtil;
import com.example.policy360.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public AuthResponse login(AuthRequest authRequest) {
        log.info("Attempting login for user: {}", authRequest.getUsername());

        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            authRequest.getUsername(),
                            authRequest.getPassword()));

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtTokenUtil.generateToken(userDetails);

            User user = userRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("User not found after authentication"));

            log.info("Successfully logged in user: {}", authRequest.getUsername());

            return AuthResponse.builder()
                    .token(token)
                    .type("Bearer")
                    .username(user.getUsername())
                    .role(user.getRole().name())
                    .expiresIn(jwtTokenUtil.getExpirationDateFromToken(token).getTime())
                    .build();

        } catch (Exception e) {
            log.error("Invalid credentials for user: {}", authRequest.getUsername());
            throw new RuntimeException("Invalid username or password");
        }
    }

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest registerRequest) {
        log.info("Attempting to register user: {}", registerRequest.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists: " + registerRequest.getUsername());
        }

        // Check if email already exists
        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("Email already exists: " + registerRequest.getEmail());
        }

        // Create new user
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());  // This will be encrypted by AttributeConverter
        user.setFullName(registerRequest.getFullName());  // This will be encrypted by AttributeConverter
        user.setMobileNumber(registerRequest.getMobileNumber());  // This will be encrypted by AttributeConverter
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));  // BCrypt encoding
        user.setRole(registerRequest.getRole());
        user.setActive(true);

        User savedUser = userRepository.save(user);

        log.info("Successfully registered user: {} with ID: {}", savedUser.getUsername(), savedUser.getId());

        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail(),  // This will be decrypted by AttributeConverter
                savedUser.getFullName(),  // This will be decrypted by AttributeConverter
                savedUser.getMobileNumber(),  // This will be decrypted by AttributeConverter
                savedUser.getRole(),
                savedUser.getCreatedAt(),
                savedUser.isActive(),
                "User registered successfully"
        );
    }
}
