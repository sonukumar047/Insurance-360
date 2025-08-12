package com.example.policy360.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JobExecutionResult {
    private String jobName;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private long durationMs;
    private String status; // RUNNING, COMPLETED, FAILED
    private int totalProcessed;
    private int successCount;
    private int failureCount;
    private String errorMessage;
    private Map<String, Object> additionalInfo;

    public static JobExecutionResult success(String jobName, int processed, int success) {
        return JobExecutionResult.builder()
                .jobName(jobName)
                .status("COMPLETED")
                .totalProcessed(processed)
                .successCount(success)
                .failureCount(processed - success)
                .build();
    }

    public static JobExecutionResult failure(String jobName, String error) {
        return JobExecutionResult.builder()
                .jobName(jobName)
                .status("FAILED")
                .errorMessage(error)
                .build();
    }
}
