package com.example.policy360.scheduler;

import com.example.policy360.service.SchedulerService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(
        value = "policy360.scheduler.enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class Policy360ScheduledJobs {

    private final SchedulerService schedulerService;

    @Scheduled(cron = "${policy360.scheduler.policy-expiration-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void sendPolicyExpirationReminders() {
        log.info("Executing scheduled job: Policy expiration reminders");
        try {
            var result = schedulerService.sendExpirationReminders();
            log.info("Policy expiration reminders completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Policy expiration reminders job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.policy-renewal-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void sendPolicyRenewalReminders() {
        log.info("Executing scheduled job: Policy renewal reminders");
        try {
            var result = schedulerService.sendRenewalReminders();
            log.info("Policy renewal reminders completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Policy renewal reminders job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.expired-policies-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void processExpiredPolicies() {
        log.info("Executing scheduled job: Process expired policies");
        try {
            var result = schedulerService.processExpiredPolicies();
            log.info("Process expired policies completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Process expired policies job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.claim-reminders-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void sendPendingClaimReminders() {
        log.info("Executing scheduled job: Pending claim reminders");
        try {
            var result = schedulerService.sendPendingClaimReminders();
            log.info("Pending claim reminders completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Pending claim reminders job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.overdue-claims-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void processOverdueClaims() {
        log.info("Executing scheduled job: Process overdue claims");
        try {
            var result = schedulerService.processOverdueClaims();
            log.info("Process overdue claims completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Process overdue claims job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.health-check-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void performHealthChecks() {
        log.debug("Executing scheduled job: Health checks");
        try {
            var result = schedulerService.performHealthChecks();
            if (!"COMPLETED".equals(result.getStatus())) {
                log.warn("Health checks detected issues: {}", result.getErrorMessage());
            }
        } catch (Exception e) {
            log.error("Health checks job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.policy-reports-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void generatePolicyReports() {
        log.info("Executing scheduled job: Generate policy reports");
        try {
            var result = schedulerService.generatePolicyReports();
            log.info("Generate policy reports completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Generate policy reports job failed", e);
        }
    }

    @Scheduled(cron = "${policy360.scheduler.archive-cron}")
    @Async("policy360AsyncTaskExecutor")
    public void archiveOldRecords() {
        log.info("Executing scheduled job: Archive old records");
        try {
            var result = schedulerService.archiveOldRecords();
            log.info("Archive old records completed: {} (Success: {}/{})",
                    result.getStatus(), result.getSuccessCount(), result.getTotalProcessed());
        } catch (Exception e) {
            log.error("Archive old records job failed", e);
        }
    }
}
