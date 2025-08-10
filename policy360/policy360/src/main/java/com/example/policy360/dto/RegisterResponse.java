package com.example.policy360.dto;

import com.example.policy360.entity.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String mobileNumber;
    private Role role;
    private LocalDateTime createdAt;
    private boolean isActive;
    private String message;
}
