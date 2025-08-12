package com.example.policy360.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SchedulerStatusDto {
    private boolean schedulerActive;
    private int totalJobs;
    private int runningJobs;
    private LocalDateTime lastHealthCheck;
    private Map<String, String> jobStatuses;
    private List<JobExecutionResult> recentExecutions;
}
