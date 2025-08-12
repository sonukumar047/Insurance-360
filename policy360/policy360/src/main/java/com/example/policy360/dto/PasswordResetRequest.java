package com.example.policy360.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Please provide a valid email address")
    private String email;
}
