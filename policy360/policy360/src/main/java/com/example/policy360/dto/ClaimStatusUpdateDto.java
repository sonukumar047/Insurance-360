package com.example.policy360.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ClaimStatusUpdateDto {
    @NotBlank(message = "Status is required")
    private String status;

    private String rejectionReason;
    private BigDecimal approvedAmount;
    private String comments;
}
