package com.example.policy360.service.Impl;

import com.example.policy360.dto.JobExecutionResult;
import com.example.policy360.dto.SchedulerStatusDto;
import com.example.policy360.entity.Claim;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.Role;
import com.example.policy360.repository.ClaimRepository;
import com.example.policy360.repository.PolicyRepository;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.service.EmailService;
import com.example.policy360.service.SchedulerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class SchedulerServiceImpl implements SchedulerService {

    private final PolicyRepository policyRepository;
    private final ClaimRepository claimRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    @Value("${policy360.scheduler.policy-expiration-reminder-days:30}")
    private int policyExpirationReminderDays;

    @Value("${policy360.scheduler.claim-reminder-days:7}")
    private int claimReminderDays;

    @Value("${policy360.scheduler.archive-days:365}")
    private int archiveDays;

    @Value("${policy360.scheduler.auto-expire-grace-days:7}")
    private int autoExpireGraceDays;

    @Value("${policy360.scheduler.overdue-claim-days:30}")
    private int overdueClaimDays;

    @Value("${policy360.notifications.batch-size:50}")
    private int notificationBatchSize;

    // Thread-safe job tracking
    private final Map<String, AtomicBoolean> runningJobs = new ConcurrentHashMap<>();
    private final Map<String, List<JobExecutionResult>> jobHistory = new ConcurrentHashMap<>();
    private final int MAX_HISTORY_SIZE = 50;

    @Override
    @Transactional
    public JobExecutionResult sendExpirationReminders() {
        return executeJob("POLICY_EXPIRATION_REMINDERS", () -> {
            log.info("Starting policy expiration reminder job");

            LocalDate today = LocalDate.now();
            LocalDate futureDate = today.plusDays(policyExpirationReminderDays);

            List<Policy> expiringPolicies = policyRepository.findAll().stream()
                    .filter(p -> p.getStatus() == PolicyStatus.ACTIVE)
                    .filter(p -> p.getEndDate().isAfter(today) && p.getEndDate().isBefore(futureDate))
                    .collect(Collectors.toList());

            int totalProcessed = 0;
            int successCount = 0;
            Map<String, Object> details = new HashMap<>();

            for (Policy policy : expiringPolicies) {
                totalProcessed++;
                try {
                    long daysUntilExpiry = policy.getDaysUntilExpiry();
                    emailService.sendPolicyExpirationReminderEmail(policy, (int) daysUntilExpiry);
                    successCount++;
                    log.debug("Sent expiration reminder for policy: {}", policy.getPolicyNumber());
                } catch (Exception e) {
                    log.error("Failed to send expiration reminder for policy: {}",
                            policy.getPolicyNumber(), e);
                }
            }

            details.put("policies_expiring_soon", expiringPolicies.size());
            details.put("reminder_threshold_days", policyExpirationReminderDays);

            return JobExecutionResult.builder()
                    .totalProcessed(totalProcessed)
                    .successCount(successCount)
                    .failureCount(totalProcessed - successCount)
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    @Transactional
    public JobExecutionResult sendRenewalReminders() {
        return executeJob("POLICY_RENEWAL_REMINDERS", () -> {
            log.info("Starting policy renewal reminder job");

            LocalDate renewalCutoff = LocalDate.now().plusDays(60);
            List<Policy> eligiblePolicies = policyRepository.findAll().stream()
                    .filter(p -> p.getStatus() == PolicyStatus.ACTIVE)
                    .filter(p -> p.getRenewalDate() != null && p.getRenewalDate().isBefore(renewalCutoff))
                    .collect(Collectors.toList());

            int totalProcessed = 0;
            int successCount = 0;

            for (Policy policy : eligiblePolicies) {
                totalProcessed++;
                try {
                    emailService.sendPolicyRenewalEmail(policy);
                    successCount++;
                    log.debug("Sent renewal reminder for policy: {}", policy.getPolicyNumber());
                } catch (Exception e) {
                    log.error("Failed to send renewal reminder for policy: {}",
                            policy.getPolicyNumber(), e);
                }
            }

            Map<String, Object> details = Map.of(
                    "eligible_policies", eligiblePolicies.size(),
                    "renewal_cutoff_days", 60
            );

            return JobExecutionResult.builder()
                    .totalProcessed(totalProcessed)
                    .successCount(successCount)
                    .failureCount(totalProcessed - successCount)
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    @Transactional
    public JobExecutionResult processExpiredPolicies() {
        return executeJob("PROCESS_EXPIRED_POLICIES", () -> {
            log.info("Starting expired policies processing job");

            LocalDate today = LocalDate.now();
            List<Policy> expiredPolicies = policyRepository.findAll().stream()
                    .filter(p -> p.getStatus() == PolicyStatus.ACTIVE)
                    .filter(p -> p.getEndDate().isBefore(today.minusDays(autoExpireGraceDays)))
                    .collect(Collectors.toList());

            int totalProcessed = 0;
            int successCount = 0;

            for (Policy policy : expiredPolicies) {
                totalProcessed++;
                try {
                    policy.setStatus(PolicyStatus.EXPIRED);
                    policy.setUpdatedBy("SYSTEM_SCHEDULER");
                    policy.setUpdatedAt(LocalDateTime.now());
                    policyRepository.save(policy);

                    emailService.sendPolicyCancellationEmail(policy,
                            "Policy automatically expired after grace period");

                    successCount++;
                    log.info("Auto-expired policy: {}", policy.getPolicyNumber());
                } catch (Exception e) {
                    log.error("Failed to process expired policy: {}", policy.getPolicyNumber(), e);
                }
            }

            Map<String, Object> details = Map.of(
                    "expired_policies_found", expiredPolicies.size(),
                    "grace_period_days", autoExpireGraceDays
            );

            return JobExecutionResult.builder()
                    .totalProcessed(totalProcessed)
                    .successCount(successCount)
                    .failureCount(totalProcessed - successCount)
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    @Transactional
    public JobExecutionResult sendPendingClaimReminders() {
        return executeJob("CLAIM_REMINDERS", () -> {
            log.info("Starting pending claim reminders job");

            LocalDateTime cutoffDate = LocalDateTime.now().minusDays(claimReminderDays);
            List<Claim> pendingClaims = claimRepository.findByStatusAndSubmittedDateBefore(
                    ClaimStatus.PENDING, cutoffDate);

            int totalProcessed = 0;
            int successCount = 0;

            for (Claim claim : pendingClaims) {
                totalProcessed++;
                try {
                    emailService.sendClaimReminderEmail(claim);
                    successCount++;
                    log.debug("Sent reminder for claim: {}", claim.getClaimNumber());
                } catch (Exception e) {
                    log.error("Failed to send reminder for claim: {}", claim.getClaimNumber(), e);
                }
            }

            Map<String, Object> details = Map.of(
                    "pending_claims_found", pendingClaims.size(),
                    "reminder_threshold_days", claimReminderDays
            );

            return JobExecutionResult.builder()
                    .totalProcessed(totalProcessed)
                    .successCount(successCount)
                    .failureCount(totalProcessed - successCount)
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    @Transactional
    public JobExecutionResult processOverdueClaims() {
        return executeJob("PROCESS_OVERDUE_CLAIMS", () -> {
            log.info("Starting overdue claims processing job");

            LocalDateTime overdueDate = LocalDateTime.now().minusDays(overdueClaimDays);
            List<Claim> overdueClaims = claimRepository.findByStatusAndSubmittedDateBefore(
                    ClaimStatus.PENDING, overdueDate);

            int totalProcessed = 0;
            int autoApproved = 0;
            int escalated = 0;

            for (Claim claim : overdueClaims) {
                totalProcessed++;
                try {
                    if (claim.getClaimAmount().compareTo(BigDecimal.valueOf(1000)) <= 0) {
                        // Auto-approve small claims
                        claim.setStatus(ClaimStatus.APPROVED);
                        claim.setApprovedAmount(claim.getClaimAmount());
                        claim.setProcessedDate(LocalDateTime.now());
                        claimRepository.save(claim);
                        emailService.sendClaimApprovalEmail(claim);
                        autoApproved++;
                    } else {
                        // Escalate larger claims
                        claim.setStatus(ClaimStatus.PROCESSING);
                        claimRepository.save(claim);
                        escalated++;
                    }
                } catch (Exception e) {
                    log.error("Failed to process overdue claim: {}", claim.getClaimNumber(), e);
                }
            }

            Map<String, Object> details = Map.of(
                    "overdue_claims_found", overdueClaims.size(),
                    "auto_approved", autoApproved,
                    "escalated", escalated,
                    "overdue_threshold_days", overdueClaimDays
            );

            return JobExecutionResult.builder()
                    .totalProcessed(totalProcessed)
                    .successCount(autoApproved + escalated)
                    .failureCount(totalProcessed - (autoApproved + escalated))
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    @Transactional(readOnly = true)
    public JobExecutionResult performHealthChecks() {
        return executeJob("HEALTH_CHECKS", () -> {
            log.debug("Performing system health checks");

            Map<String, Object> healthStatus = new HashMap<>();
            int checksPerformed = 0;
            int checksSucceeded = 0;

            // Database connectivity check
            checksPerformed++;
            try {
                long policyCount = policyRepository.count();
                healthStatus.put("database", "OK - " + policyCount + " policies");
                checksSucceeded++;
            } catch (Exception e) {
                healthStatus.put("database", "ERROR - " + e.getMessage());
            }

            // Memory usage check
            checksPerformed++;
            try {
                Runtime runtime = Runtime.getRuntime();
                long totalMemory = runtime.totalMemory();
                long freeMemory = runtime.freeMemory();
                double usagePercent = (double) (totalMemory - freeMemory) / totalMemory * 100;

                if (usagePercent < 80) {
                    healthStatus.put("memory", String.format("OK - %.1f%% used", usagePercent));
                    checksSucceeded++;
                } else {
                    healthStatus.put("memory", String.format("WARNING - %.1f%% used", usagePercent));
                }
            } catch (Exception e) {
                healthStatus.put("memory", "ERROR - " + e.getMessage());
            }

            return JobExecutionResult.builder()
                    .totalProcessed(checksPerformed)
                    .successCount(checksSucceeded)
                    .failureCount(checksPerformed - checksSucceeded)
                    .additionalInfo(healthStatus)
                    .build();
        });
    }

    // Additional method implementations for interface compliance
    @Override
    public JobExecutionResult generatePolicyReports() {
        return executeJob("POLICY_REPORTS", () -> {
            log.info("Generating policy reports");

            // Generate business analytics
            long totalPolicies = policyRepository.count();
            long activePolicies = policyRepository.findByStatus(PolicyStatus.ACTIVE).size();

            Map<String, Object> reportData = Map.of(
                    "total_policies", totalPolicies,
                    "active_policies", activePolicies,
                    "report_date", LocalDate.now()
            );

            return JobExecutionResult.builder()
                    .totalProcessed(1)
                    .successCount(1)
                    .additionalInfo(reportData)
                    .build();
        });
    }

    @Override
    public JobExecutionResult generateClaimReports() {
        return executeJob("CLAIM_REPORTS", () -> {
            log.info("Generating claim reports");

            long totalClaims = claimRepository.count();
            long pendingClaims = claimRepository.findByStatus(ClaimStatus.PENDING).size();

            Map<String, Object> reportData = Map.of(
                    "total_claims", totalClaims,
                    "pending_claims", pendingClaims,
                    "report_date", LocalDate.now()
            );

            return JobExecutionResult.builder()
                    .totalProcessed(1)
                    .successCount(1)
                    .additionalInfo(reportData)
                    .build();
        });
    }

    @Override
    public JobExecutionResult archiveOldRecords() {
        return executeJob("ARCHIVE_OLD_RECORDS", () -> {
            log.info("Starting old records archival job");

            LocalDateTime archiveDate = LocalDateTime.now().minusDays(archiveDays);

            // Count records that would be archived
            long oldPolicies = policyRepository.findAll().stream()
                    .filter(p -> p.getStatus().isTerminal())
                    .filter(p -> p.getUpdatedAt().isBefore(archiveDate))
                    .count();

            long oldClaims = claimRepository.findAll().stream()
                    .filter(c -> c.getStatus().isTerminal())
                    .filter(c -> c.getUpdatedAt().isBefore(archiveDate))
                    .count();

            Map<String, Object> details = Map.of(
                    "old_policies", oldPolicies,
                    "old_claims", oldClaims,
                    "archive_cutoff_days", archiveDays
            );

            return JobExecutionResult.builder()
                    .totalProcessed((int) (oldPolicies + oldClaims))
                    .successCount((int) (oldPolicies + oldClaims))
                    .additionalInfo(details)
                    .build();
        });
    }

    @Override
    public JobExecutionResult generateSystemReports() {
        return executeJob("SYSTEM_REPORTS", () -> {
            log.info("Generating system reports");
            return JobExecutionResult.success("SYSTEM_REPORTS", 1, 1);
        });
    }

    @Override
    public JobExecutionResult processAutoRenewals() {
        return executeJob("AUTO_RENEWALS", () -> {
            log.info("Processing automatic renewals");
            return JobExecutionResult.success("AUTO_RENEWALS", 0, 0);
        });
    }

    @Override
    public JobExecutionResult sendPaymentReminders() {
        return executeJob("PAYMENT_REMINDERS", () -> {
            log.info("Sending payment reminders");
            return JobExecutionResult.success("PAYMENT_REMINDERS", 0, 0);
        });
    }

    // Monitoring and management methods
    @Override
    public SchedulerStatusDto getSchedulerStatus() {
        Map<String, String> jobStatuses = runningJobs.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().get() ? "RUNNING" : "IDLE"
                ));

        List<JobExecutionResult> recentExecutions = jobHistory.values().stream()
                .flatMap(List::stream)
                .sorted((a, b) -> b.getStartTime().compareTo(a.getStartTime()))
                .limit(10)
                .collect(Collectors.toList());

        return SchedulerStatusDto.builder()
                .schedulerActive(true)
                .totalJobs(runningJobs.size())
                .runningJobs((int) runningJobs.values().stream().mapToLong(ab -> ab.get() ? 1 : 0).sum())
                .lastHealthCheck(LocalDateTime.now())
                .jobStatuses(jobStatuses)
                .recentExecutions(recentExecutions)
                .build();
    }

    @Override
    public boolean isJobRunning(String jobName) {
        return runningJobs.getOrDefault(jobName, new AtomicBoolean(false)).get();
    }

    @Override
    public List<JobExecutionResult> getJobHistory(String jobName, int limit) {
        return jobHistory.getOrDefault(jobName, new ArrayList<>()).stream()
                .sorted((a, b) -> b.getStartTime().compareTo(a.getStartTime()))
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public JobExecutionResult executeJobManually(String jobName) {
        return switch (jobName.toUpperCase()) {
            case "POLICY_EXPIRATION_REMINDERS" -> sendExpirationReminders();
            case "POLICY_RENEWAL_REMINDERS" -> sendRenewalReminders();
            case "PROCESS_EXPIRED_POLICIES" -> processExpiredPolicies();
            case "CLAIM_REMINDERS" -> sendPendingClaimReminders();
            case "PROCESS_OVERDUE_CLAIMS" -> processOverdueClaims();
            case "HEALTH_CHECKS" -> performHealthChecks();
            case "POLICY_REPORTS" -> generatePolicyReports();
            case "CLAIM_REPORTS" -> generateClaimReports();
            case "ARCHIVE_OLD_RECORDS" -> archiveOldRecords();
            default -> JobExecutionResult.failure(jobName, "Unknown job name: " + jobName);
        };
    }

    // Helper methods
    private JobExecutionResult executeJob(String jobName, JobExecutor executor) {
        AtomicBoolean jobFlag = runningJobs.computeIfAbsent(jobName, k -> new AtomicBoolean(false));

        if (!jobFlag.compareAndSet(false, true)) {
            log.warn("Job {} is already running, skipping execution", jobName);
            return JobExecutionResult.failure(jobName, "Job already running");
        }

        LocalDateTime startTime = LocalDateTime.now();
        JobExecutionResult result = null;

        try {
            result = executor.execute();
            result.setJobName(jobName);
            result.setStartTime(startTime);
            result.setEndTime(LocalDateTime.now());
            result.setDurationMs(Duration.between(startTime, result.getEndTime()).toMillis());

            if (result.getStatus() == null) {
                result.setStatus("COMPLETED");
            }

        } catch (Exception e) {
            log.error("Job {} failed with exception", jobName, e);
            result = JobExecutionResult.failure(jobName, e.getMessage());
            result.setStartTime(startTime);
            result.setEndTime(LocalDateTime.now());
            result.setDurationMs(Duration.between(startTime, result.getEndTime()).toMillis());
        } finally {
            jobFlag.set(false);
            addToJobHistory(jobName, result);
        }

        return result;
    }

    private void addToJobHistory(String jobName, JobExecutionResult result) {
        jobHistory.computeIfAbsent(jobName, k -> new ArrayList<>()).add(result);

        // Keep only the last N executions
        List<JobExecutionResult> history = jobHistory.get(jobName);
        if (history.size() > MAX_HISTORY_SIZE) {
            history.sort((a, b) -> b.getStartTime().compareTo(a.getStartTime()));
            jobHistory.put(jobName, history.subList(0, MAX_HISTORY_SIZE));
        }
    }

    @FunctionalInterface
    private interface JobExecutor {
        JobExecutionResult execute() throws Exception;
    }
}
