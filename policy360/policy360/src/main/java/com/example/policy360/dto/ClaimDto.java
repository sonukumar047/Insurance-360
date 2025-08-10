package com.example.policy360.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClaimDto {

    private Long id;
    private String claimNumber;

    @NotNull(message = "Policy ID is required")
    private Long policyId;

    @NotBlank(message = "Description is required")
    private String description;

    @NotNull(message = "Claim amount is required")
    @Positive(message = "Claim amount must be positive")
    private BigDecimal claimAmount;

    private String status;

    @NotNull(message = "Incident date is required")
    private LocalDateTime incidentDate;

    private LocalDateTime submittedDate;
    private LocalDateTime processedDate;
}
