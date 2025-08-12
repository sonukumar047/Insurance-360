package com.example.policy360.config;

import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        createInitialUsers();
    }

    private void createInitialUsers() {
        // Create admin user
        createUserIfNotExists("admin", "admin@policy360.com", "System Administrator", "1234567890", "admin123", Role.ADMIN);

        // Create agent user
        createUserIfNotExists("agent_user", "agent@policy360.com", "Agent User", "7777777777", "agent123", Role.AGENT);

        // Create customer user
        createUserIfNotExists("john_customer", "john@example.com", "John Customer", "1234567890", "password123", Role.CUSTOMER);
    }

    private void createUserIfNotExists(String username, String email, String fullName, String mobile, String password, Role role) {
        if (userRepository.findByUsername(username).isEmpty()) {
            User user = User.builder()
                    .username(username)
                    .email(email)
                    .fullName(fullName)
                    .mobileNumber(mobile)
                    .password(passwordEncoder.encode(password))
                    .role(role)
                    .isActive(true)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();

            userRepository.save(user);
            log.info("Created {} user: {} (password: {})", role, username, password);
        } else {
            log.info("{} user '{}' already exists", role, username);
        }
    }
}
