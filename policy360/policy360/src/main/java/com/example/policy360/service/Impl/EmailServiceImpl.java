package com.example.policy360.service.Impl;

import com.example.policy360.entity.Claim;
import com.example.policy360.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendClaimReminderEmail(Claim claim) {
        log.info("Sending claim reminder email for claim: {}", claim.getClaimNumber());

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(claim.getPolicy().getCustomer().getEmail());
        message.setSubject("Policy360 - Claim Status Reminder");
        message.setText(buildClaimReminderEmailContent(claim));

        try {
            mailSender.send(message);
            log.info("Claim reminder email sent successfully for claim: {}", claim.getClaimNumber());
        } catch (Exception e) {
            log.error("Failed to send claim reminder email for claim: {}", claim.getClaimNumber(), e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Override
    public void sendWelcomeEmail(String email, String username) {
        log.info("Sending welcome email to: {}", email);

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Welcome to Policy360");
        message.setText(buildWelcomeEmailContent(username));

        try {
            mailSender.send(message);
            log.info("Welcome email sent successfully to: {}", email);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", email, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Override
    public void sendClaimStatusUpdateEmail(Claim claim) {
        log.info("Sending claim status update email for claim: {}", claim.getClaimNumber());

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(claim.getPolicy().getCustomer().getEmail());
        message.setSubject("Policy360 - Claim Status Update");
        message.setText(buildClaimStatusUpdateEmailContent(claim));

        try {
            mailSender.send(message);
            log.info("Claim status update email sent successfully for claim: {}", claim.getClaimNumber());
        } catch (Exception e) {
            log.error("Failed to send claim status update email for claim: {}", claim.getClaimNumber(), e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    private String buildClaimReminderEmailContent(Claim claim) {
        return String.format(
                "Dear %s,\n\n" +
                        "This is a reminder that your claim %s is still pending.\n\n" +
                        "Claim Details:\n" +
                        "- Claim Number: %s\n" +
                        "- Policy Number: %s\n" +
                        "- Claim Amount: $%s\n" +
                        "- Submitted Date: %s\n\n" +
                        "We are working to process your claim as soon as possible.\n\n" +
                        "Best regards,\n" +
                        "Policy360 Team",
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                claim.getClaimAmount(),
                claim.getSubmittedDate()
        );
    }

    private String buildWelcomeEmailContent(String username) {
        return String.format(
                "Dear %s,\n\n" +
                        "Welcome to Policy360! Your account has been successfully created.\n\n" +
                        "You can now access our secure insurance management system.\n\n" +
                        "If you have any questions, please contact our support team.\n\n" +
                        "Best regards,\n" +
                        "Policy360 Team",
                username
        );
    }

    private String buildClaimStatusUpdateEmailContent(Claim claim) {
        return String.format(
                "Dear %s,\n\n" +
                        "Your claim status has been updated.\n\n" +
                        "Claim Details:\n" +
                        "- Claim Number: %s\n" +
                        "- Policy Number: %s\n" +
                        "- New Status: %s\n" +
                        "- Claim Amount: $%s\n" +
                        "- Updated Date: %s\n\n" +
                        "Thank you for choosing Policy360.\n\n" +
                        "Best regards,\n" +
                        "Policy360 Team",
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                claim.getStatus().name(),
                claim.getClaimAmount(),
                claim.getUpdatedAt()
        );
    }
}
