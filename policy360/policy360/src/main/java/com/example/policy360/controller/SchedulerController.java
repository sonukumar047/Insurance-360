// src/main/java/com/example/policy360/controller/SchedulerController.java
package com.example.policy360.controller;

import com.example.policy360.dto.JobExecutionResult;
import com.example.policy360.dto.SchedulerStatusDto;
import com.example.policy360.service.SchedulerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin/scheduler")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class SchedulerController {

    private final SchedulerService schedulerService;

    @GetMapping("/status")
    public ResponseEntity<SchedulerStatusDto> getSchedulerStatus() {
        log.info("Admin requesting scheduler status");
        try {
            SchedulerStatusDto status = schedulerService.getSchedulerStatus();
            return ResponseEntity.ok(status);
        } catch (Exception e) {
            log.error("Error getting scheduler status", e);
            throw new RuntimeException("Failed to get scheduler status: " + e.getMessage());
        }
    }

    @GetMapping("/jobs/{jobName}/history")
    public ResponseEntity<List<JobExecutionResult>> getJobHistory(
            @PathVariable String jobName,
            @RequestParam(defaultValue = "10") int limit) {
        log.info("Admin requesting job history for: {} (limit: {})", jobName, limit);
        try {
            List<JobExecutionResult> history = schedulerService.getJobHistory(jobName, limit);
            return ResponseEntity.ok(history);
        } catch (Exception e) {
            log.error("Error getting job history for: {}", jobName, e);
            throw new RuntimeException("Failed to get job history: " + e.getMessage());
        }
    }

    @PostMapping("/jobs/{jobName}/execute")
    public ResponseEntity<JobExecutionResult> executeJob(@PathVariable String jobName) {
        log.info("Admin manually executing job: {}", jobName);
        try {
            JobExecutionResult result = schedulerService.executeJobManually(jobName);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing job: {}", jobName, e);
            throw new RuntimeException("Failed to execute job: " + e.getMessage());
        }
    }

    // Specific endpoint implementations for Postman collection compatibility
    @PostMapping("/execute/policy-expiration-reminders")
    public ResponseEntity<JobExecutionResult> executePolicyExpirationReminders() {
        log.info("Manual execution: Policy expiration reminders");
        try {
            JobExecutionResult result = schedulerService.sendExpirationReminders();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing policy expiration reminders", e);
            throw new RuntimeException("Failed to execute policy expiration reminders: " + e.getMessage());
        }
    }

    @PostMapping("/execute/policy-renewal-reminders")
    public ResponseEntity<JobExecutionResult> executePolicyRenewalReminders() {
        log.info("Manual execution: Policy renewal reminders");
        try {
            JobExecutionResult result = schedulerService.sendRenewalReminders();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing policy renewal reminders", e);
            throw new RuntimeException("Failed to execute policy renewal reminders: " + e.getMessage());
        }
    }

    @PostMapping("/execute/claim-reminders")
    public ResponseEntity<JobExecutionResult> executeClaimReminders() {
        log.info("Manual execution: Claim reminders");
        try {
            JobExecutionResult result = schedulerService.sendPendingClaimReminders();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing claim reminders", e);
            throw new RuntimeException("Failed to execute claim reminders: " + e.getMessage());
        }
    }

    @PostMapping("/execute/process-overdue-claims")
    public ResponseEntity<JobExecutionResult> executeProcessOverdueClaims() {
        log.info("Manual execution: Process overdue claims");
        try {
            JobExecutionResult result = schedulerService.processOverdueClaims();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing process overdue claims", e);
            throw new RuntimeException("Failed to execute process overdue claims: " + e.getMessage());
        }
    }

    @PostMapping("/execute/process-expired-policies")
    public ResponseEntity<JobExecutionResult> executeProcessExpiredPolicies() {
        log.info("Manual execution: Process expired policies");
        try {
            JobExecutionResult result = schedulerService.processExpiredPolicies();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing process expired policies", e);
            throw new RuntimeException("Failed to execute process expired policies: " + e.getMessage());
        }
    }

    @PostMapping("/execute/archive-old-records")
    public ResponseEntity<JobExecutionResult> executeArchiveOldRecords() {
        log.info("Manual execution: Archive old records");
        try {
            JobExecutionResult result = schedulerService.archiveOldRecords();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing archive old records", e);
            throw new RuntimeException("Failed to execute archive old records: " + e.getMessage());
        }
    }

    @PostMapping("/execute/health-checks")
    public ResponseEntity<JobExecutionResult> executeHealthChecks() {
        log.info("Manual execution: Health checks");
        try {
            JobExecutionResult result = schedulerService.performHealthChecks();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing health checks", e);
            throw new RuntimeException("Failed to execute health checks: " + e.getMessage());
        }
    }

    @PostMapping("/execute/policy-reports")
    public ResponseEntity<JobExecutionResult> executePolicyReports() {
        log.info("Manual execution: Policy reports");
        try {
            JobExecutionResult result = schedulerService.generatePolicyReports();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing policy reports", e);
            throw new RuntimeException("Failed to execute policy reports: " + e.getMessage());
        }
    }

    @PostMapping("/execute/claim-reports")
    public ResponseEntity<JobExecutionResult> executeClaimReports() {
        log.info("Manual execution: Claim reports");
        try {
            JobExecutionResult result = schedulerService.generateClaimReports();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing claim reports", e);
            throw new RuntimeException("Failed to execute claim reports: " + e.getMessage());
        }
    }

    @PostMapping("/execute/system-reports")
    public ResponseEntity<JobExecutionResult> executeSystemReports() {
        log.info("Manual execution: System reports");
        try {
            JobExecutionResult result = schedulerService.generateSystemReports();
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Error executing system reports", e);
            throw new RuntimeException("Failed to execute system reports: " + e.getMessage());
        }
    }
}
