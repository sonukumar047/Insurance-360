package com.example.policy360.scheduler;

import com.example.policy360.entity.Claim;
import com.example.policy360.repository.ClaimRepository;
import com.example.policy360.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "scheduler.claim-reminder.enabled", havingValue = "true")
public class ClaimReminderScheduler {

    private final ClaimRepository claimRepository;
    private final EmailService emailService;

    @Scheduled(cron = "${scheduler.claim-reminder.cron}")
    public void sendClaimReminders() {
        log.info("Starting claim reminder scheduler");

        List<Claim> pendingClaims = claimRepository.findPendingClaimsOlderThanWeek();

        for (Claim claim : pendingClaims) {
            try {
                emailService.sendClaimReminderEmail(claim);
                log.info("Sent reminder email for claim: {}", claim.getClaimNumber());
            } catch (Exception e) {
                log.error("Failed to send reminder email for claim: {}", claim.getClaimNumber(), e);
            }
        }

        log.info("Completed claim reminder scheduler. Processed {} claims", pendingClaims.size());
    }
}
