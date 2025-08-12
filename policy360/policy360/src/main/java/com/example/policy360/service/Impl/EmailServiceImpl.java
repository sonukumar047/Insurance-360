package com.example.policy360.service.Impl;

import com.example.policy360.dto.EmailDto;
import com.example.policy360.entity.Claim;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.ClaimStatus;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.exception.EmailServiceException;
import com.example.policy360.service.EmailService;
import com.example.policy360.util.EmailTemplateUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final EmailTemplateUtil templateUtil;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.name:Policy360}")
    private String appName;

    @Value("${app.support.email:support@policy360.com}")
    private String supportEmail;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$");

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("MMM dd, yyyy");
    private static final DateTimeFormatter DATETIME_FORMATTER = DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' hh:mm a");

    // CLAIM-RELATED EMAIL METHODS

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendClaimReminderEmail(Claim claim) {
        log.info("Sending claim reminder email for claim: {}", claim.getClaimNumber());

        try {
            validateClaimForEmail(claim);

            String customerEmail = claim.getPolicy().getCustomer().getEmail();
            if (!isValidEmail(customerEmail)) {
                throw new EmailServiceException("Invalid customer email address: " + customerEmail);
            }

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Claim Status Reminder");
            helper.setText(buildClaimReminderEmailContent(claim), true);

            mailSender.send(message);
            log.info("Claim reminder email sent successfully for claim: {} to: {}",
                    claim.getClaimNumber(), customerEmail);

        } catch (MessagingException e) {
            log.error("Failed to create claim reminder email for claim: {}", claim.getClaimNumber(), e);
            throw new EmailServiceException("Failed to create email message", e);
        } catch (MailException e) {
            log.error("Failed to send claim reminder email for claim: {}", claim.getClaimNumber(), e);
            throw new EmailServiceException("Failed to send email", e);
        }
    }

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendClaimStatusUpdateEmail(Claim claim) {
        log.info("Sending claim status update email for claim: {}", claim.getClaimNumber());

        try {
            validateClaimForEmail(claim);

            String customerEmail = claim.getPolicy().getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Claim Status Update");
            helper.setText(buildClaimStatusUpdateEmailContent(claim), true);

            mailSender.send(message);
            log.info("Claim status update email sent successfully for claim: {} to: {}",
                    claim.getClaimNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send claim status update email for claim: {}", claim.getClaimNumber(), e);
            throw new EmailServiceException("Failed to send claim status update email", e);
        }
    }

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendClaimApprovalEmail(Claim claim) {
        log.info("Sending claim approval email for claim: {}", claim.getClaimNumber());

        try {
            validateClaimForEmail(claim);

            String customerEmail = claim.getPolicy().getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Claim Approved ✅");
            helper.setText(buildClaimApprovalEmailContent(claim), true);

            mailSender.send(message);
            log.info("Claim approval email sent successfully for claim: {} to: {}",
                    claim.getClaimNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send claim approval email for claim: {}", claim.getClaimNumber(), e);
            throw new EmailServiceException("Failed to send claim approval email", e);
        }
    }

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendClaimRejectionEmail(Claim claim, String reason) {
        log.info("Sending claim rejection email for claim: {}", claim.getClaimNumber());

        try {
            validateClaimForEmail(claim);

            String customerEmail = claim.getPolicy().getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Claim Decision Required");
            helper.setText(buildClaimRejectionEmailContent(claim, reason), true);

            mailSender.send(message);
            log.info("Claim rejection email sent successfully for claim: {} to: {}",
                    claim.getClaimNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send claim rejection email for claim: {}", claim.getClaimNumber(), e);
            throw new EmailServiceException("Failed to send claim rejection email", e);
        }
    }

    // USER-RELATED EMAIL METHODS

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendWelcomeEmail(String email, String username) {
        log.info("Sending welcome email to: {}", email);

        if (!isValidEmail(email)) {
            throw new EmailServiceException("Invalid email address: " + email);
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Welcome to " + appName + " 🎉");
            helper.setText(buildWelcomeEmailContent(username, email), true);

            mailSender.send(message);
            log.info("Welcome email sent successfully to: {}", email);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send welcome email to: {}", email, e);
            throw new EmailServiceException("Failed to send welcome email", e);
        }
    }

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendPasswordResetEmail(String email, String resetToken) {
        log.info("Sending password reset email to: {}", email);

        if (!isValidEmail(email)) {
            throw new EmailServiceException("Invalid email address: " + email);
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject(appName + " - Password Reset Request");
            helper.setText(buildPasswordResetEmailContent(resetToken), true);

            mailSender.send(message);
            log.info("Password reset email sent successfully to: {}", email);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send password reset email to: {}", email, e);
            throw new EmailServiceException("Failed to send password reset email", e);
        }
    }

    @Override
    @Async
    public void sendAccountActivationEmail(String email, String activationLink) {
        log.info("Sending account activation email to: {}", email);

        if (!isValidEmail(email)) {
            throw new EmailServiceException("Invalid email address: " + email);
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject(appName + " - Activate Your Account");
            helper.setText(buildAccountActivationEmailContent(activationLink), true);

            mailSender.send(message);
            log.info("Account activation email sent successfully to: {}", email);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send account activation email to: {}", email, e);
            throw new EmailServiceException("Failed to send account activation email", e);
        }
    }

    // POLICY-RELATED EMAIL METHODS

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendPolicyCreatedEmail(Policy policy) {
        log.info("Sending policy created email for policy: {}", policy.getPolicyNumber());

        try {
            validatePolicyForEmail(policy);

            String customerEmail = policy.getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - New Policy Created 📋");
            helper.setText(buildPolicyCreatedEmailContent(policy), true);

            mailSender.send(message);
            log.info("Policy created email sent successfully for policy: {} to: {}",
                    policy.getPolicyNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send policy created email for policy: {}", policy.getPolicyNumber(), e);
            throw new EmailServiceException("Failed to send policy created email", e);
        }
    }

    @Override
    @Async
    @Retryable(value = {MailException.class}, maxAttempts = 3, backoff = @Backoff(delay = 2000))
    public void sendPolicyExpirationReminderEmail(Policy policy, int daysUntilExpiry) {
        log.info("Sending policy expiration reminder email for policy: {}", policy.getPolicyNumber());

        try {
            validatePolicyForEmail(policy);

            String customerEmail = policy.getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Policy Expiration Reminder ⏰");
            helper.setText(buildPolicyExpirationReminderContent(policy, daysUntilExpiry), true);

            mailSender.send(message);
            log.info("Policy expiration reminder email sent successfully for policy: {} to: {}",
                    policy.getPolicyNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send policy expiration reminder email for policy: {}", policy.getPolicyNumber(), e);
            throw new EmailServiceException("Failed to send policy expiration reminder email", e);
        }
    }

    @Override
    @Async
    public void sendPolicyRenewalEmail(Policy policy) {
        log.info("Sending policy renewal email for policy: {}", policy.getPolicyNumber());

        try {
            validatePolicyForEmail(policy);

            String customerEmail = policy.getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Policy Renewed Successfully ✅");
            helper.setText(buildPolicyRenewalEmailContent(policy), true);

            mailSender.send(message);
            log.info("Policy renewal email sent successfully for policy: {} to: {}",
                    policy.getPolicyNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send policy renewal email for policy: {}", policy.getPolicyNumber(), e);
            throw new EmailServiceException("Failed to send policy renewal email", e);
        }
    }

    @Override
    @Async
    public void sendPolicyCancellationEmail(Policy policy, String reason) {
        log.info("Sending policy cancellation email for policy: {}", policy.getPolicyNumber());

        try {
            validatePolicyForEmail(policy);

            String customerEmail = policy.getCustomer().getEmail();
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(customerEmail);
            helper.setSubject(appName + " - Policy Cancellation Notice");
            helper.setText(buildPolicyCancellationEmailContent(policy, reason), true);

            mailSender.send(message);
            log.info("Policy cancellation email sent successfully for policy: {} to: {}",
                    policy.getPolicyNumber(), customerEmail);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send policy cancellation email for policy: {}", policy.getPolicyNumber(), e);
            throw new EmailServiceException("Failed to send policy cancellation email", e);
        }
    }

    // BATCH EMAIL OPERATIONS

    @Override
    @Async
    public void sendBulkEmails(List<EmailDto> emails) {
        log.info("Sending bulk emails. Count: {}", emails.size());

        CompletableFuture<Void>[] futures = emails.stream()
                .map(emailDto -> CompletableFuture.runAsync(() -> {
                    try {
                        sendTemplateEmail(emailDto.getTo(), emailDto.getSubject(),
                                emailDto.getTemplateName(), emailDto.getData());
                    } catch (Exception e) {
                        log.error("Failed to send bulk email to: {}", emailDto.getTo(), e);
                    }
                }))
                .toArray(CompletableFuture[]::new);

        CompletableFuture.allOf(futures).join();
        log.info("Bulk email sending completed");
    }

    @Override
    @Async
    public void sendClaimReminders(List<Claim> pendingClaims) {
        log.info("Sending claim reminders. Count: {}", pendingClaims.size());

        pendingClaims.forEach(claim -> {
            try {
                sendClaimReminderEmail(claim);
            } catch (Exception e) {
                log.error("Failed to send claim reminder for claim: {}", claim.getClaimNumber(), e);
            }
        });

        log.info("Claim reminders sent successfully");
    }

    @Override
    @Async
    public void sendExpirationReminders(List<Policy> expiringPolicies) {
        log.info("Sending expiration reminders. Count: {}", expiringPolicies.size());

        expiringPolicies.forEach(policy -> {
            try {
                int daysUntilExpiry = (int) policy.getDaysUntilExpiry();
                sendPolicyExpirationReminderEmail(policy, daysUntilExpiry);
            } catch (Exception e) {
                log.error("Failed to send expiration reminder for policy: {}", policy.getPolicyNumber(), e);
            }
        });

        log.info("Expiration reminders sent successfully");
    }

    // TEMPLATE-BASED EMAIL

    @Override
    @Async
    public void sendTemplateEmail(String to, String subject, String templateName, Object data) {
        log.info("Sending template email to: {} using template: {}", to, templateName);

        if (!isValidEmail(to)) {
            throw new EmailServiceException("Invalid email address: " + to);
        }

        try {
            String htmlContent = templateUtil.processTemplate(templateName, data);

            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Template email sent successfully to: {}", to);

        } catch (MessagingException | MailException e) {
            log.error("Failed to send template email to: {}", to, e);
            throw new EmailServiceException("Failed to send template email", e);
        }
    }

    // VALIDATION METHODS

    @Override
    public boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email).matches();
    }

    private void validateClaimForEmail(Claim claim) {
        if (claim == null) {
            throw new EmailServiceException("Claim cannot be null");
        }
        if (claim.getPolicy() == null) {
            throw new EmailServiceException("Claim policy cannot be null");
        }
        if (claim.getPolicy().getCustomer() == null) {
            throw new EmailServiceException("Claim policy customer cannot be null");
        }
        if (!isValidEmail(claim.getPolicy().getCustomer().getEmail())) {
            throw new EmailServiceException("Invalid customer email address");
        }
    }

    private void validatePolicyForEmail(Policy policy) {
        if (policy == null) {
            throw new EmailServiceException("Policy cannot be null");
        }
        if (policy.getCustomer() == null) {
            throw new EmailServiceException("Policy customer cannot be null");
        }
        if (!isValidEmail(policy.getCustomer().getEmail())) {
            throw new EmailServiceException("Invalid customer email address");
        }
    }

    // EMAIL CONTENT BUILDERS - HTML FORMATTED

    private String buildClaimReminderEmailContent(Claim claim) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c5530;">Claim Status Reminder</h2>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>This is a friendly reminder that your insurance claim is currently being processed.</p>
                    
                    <div style="background-color: #f8f9fa; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0;">
                        <h3 style="color: #007bff; margin-top: 0;">Claim Details</h3>
                        <p><strong>Claim Number:</strong> %s</p>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Claim Amount:</strong> $%,.2f</p>
                        <p><strong>Submitted Date:</strong> %s</p>
                        <p><strong>Current Status:</strong> <span style="color: #ffc107;">%s</span></p>
                    </div>
                    
                    <p>We are working diligently to process your claim as quickly as possible. If you have any questions or need to provide additional information, please contact our support team.</p>
                    
                    <div style="margin: 30px 0;">
                        <a href="%s/claim/%d" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">View Claim Status</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Best regards,<br>
                        <strong>%s Team</strong><br>
                        Email: %s<br>
                        This is an automated message, please do not reply to this email.
                    </p>
                </div>
            </body>
            </html>
            """,
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                claim.getClaimAmount(),
                claim.getSubmittedDate().format(DATE_FORMATTER),
                claim.getStatus().name(),
                baseUrl,
                claim.getId(),
                appName,
                supportEmail
        );
    }

    private String buildClaimStatusUpdateEmailContent(Claim claim) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #2c5530;">Claim Status Update</h2>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>We have an important update regarding your insurance claim.</p>
                    
                    <div style="background-color: #f8f9fa; padding: 20px; border-left: 4px solid #28a745; margin: 20px 0;">
                        <h3 style="color: #28a745; margin-top: 0;">Updated Claim Information</h3>
                        <p><strong>Claim Number:</strong> %s</p>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>New Status:</strong> <span style="color: %s; font-weight: bold;">%s</span></p>
                        <p><strong>Claim Amount:</strong> $%,.2f</p>
                        <p><strong>Updated On:</strong> %s</p>
                    </div>
                    
                    %s
                    
                    <div style="margin: 30px 0;">
                        <a href="%s/claim/%d" style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">View Full Details</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Thank you for choosing <strong>%s</strong>.<br><br>
                        Best regards,<br>
                        <strong>%s Claims Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                getStatusColor(claim.getStatus()),
                claim.getStatus().name(),
                claim.getClaimAmount(),
                claim.getUpdatedAt().format(DATETIME_FORMATTER),
                getStatusMessage(claim.getStatus()),
                baseUrl,
                claim.getId(),
                appName,
                appName,
                supportEmail
        );
    }

    private String buildClaimApprovalEmailContent(Claim claim) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #28a745; margin: 0;">🎉 Great News!</h1>
                        <h2 style="color: #2c5530; margin: 10px 0;">Your Claim Has Been Approved</h2>
                    </div>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>We are pleased to inform you that your insurance claim has been <strong style="color: #28a745;">APPROVED</strong>!</p>
                    
                    <div style="background-color: #d4edda; padding: 20px; border-left: 4px solid #28a745; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #155724; margin-top: 0;">Approved Claim Details</h3>
                        <p><strong>Claim Number:</strong> %s</p>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Approved Amount:</strong> <span style="color: #28a745; font-size: 18px; font-weight: bold;">$%,.2f</span></p>
                        <p><strong>Approval Date:</strong> %s</p>
                    </div>
                    
                    <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #856404; margin-top: 0;">Next Steps</h4>
                        <p style="margin: 5px 0;">• Payment processing will begin within 2-3 business days</p>
                        <p style="margin: 5px 0;">• You will receive a separate notification once payment is issued</p>
                        <p style="margin: 5px 0;">• Keep this email for your records</p>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/claim/%d" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">View Claim Details</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Thank you for choosing <strong>%s</strong> for your insurance needs.<br><br>
                        Best regards,<br>
                        <strong>%s Claims Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                claim.getClaimAmount(),
                claim.getUpdatedAt().format(DATE_FORMATTER),
                baseUrl,
                claim.getId(),
                appName,
                appName,
                supportEmail
        );
    }

    private String buildClaimRejectionEmailContent(Claim claim, String reason) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #dc3545;">Claim Decision Update</h2>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>After careful review of your insurance claim, we regret to inform you that we are unable to approve it at this time.</p>
                    
                    <div style="background-color: #f8d7da; padding: 20px; border-left: 4px solid #dc3545; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #721c24; margin-top: 0;">Claim Information</h3>
                        <p><strong>Claim Number:</strong> %s</p>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Claim Amount:</strong> $%,.2f</p>
                        <p><strong>Decision Date:</strong> %s</p>
                        <p><strong>Status:</strong> <span style="color: #dc3545; font-weight: bold;">REJECTED</span></p>
                    </div>
                    
                    <div style="background-color: #fff3cd; padding: 20px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #856404; margin-top: 0;">Reason for Decision</h4>
                        <p>%s</p>
                    </div>
                    
                    <div style="background-color: #cce7ff; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #004085; margin-top: 0;">Your Options</h4>
                        <p>If you believe this decision was made in error, you have the following options:</p>
                        <ul style="margin: 10px 0;">
                            <li>Submit additional documentation to support your claim</li>
                            <li>Request a review of the decision</li>
                            <li>Contact our claims department for clarification</li>
                        </ul>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/claim/%d" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin-right: 10px;">View Claim</a>
                        <a href="mailto:%s" style="background-color: #6c757d; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Contact Support</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        We appreciate your understanding and look forward to serving you better in the future.<br><br>
                        Best regards,<br>
                        <strong>%s Claims Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                claim.getPolicy().getCustomer().getFullName(),
                claim.getClaimNumber(),
                claim.getPolicy().getPolicyNumber(),
                claim.getClaimAmount(),
                claim.getUpdatedAt().format(DATE_FORMATTER),
                reason != null ? reason : "Please contact our support team for detailed information about this decision.",
                baseUrl,
                claim.getId(),
                supportEmail,
                appName,
                supportEmail
        );
    }

    private String buildWelcomeEmailContent(String username, String email) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px; padding: 30px; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); border-radius: 10px;">
                        <h1 style="color: white; margin: 0; font-size: 28px;">🎉 Welcome to %s!</h1>
                        <p style="color: #f8f9fa; margin: 10px 0; font-size: 16px;">Your Insurance Management Journey Starts Here</p>
                    </div>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>Welcome to the %s family! We're thrilled to have you on board. Your account has been successfully created and you're now ready to explore our comprehensive insurance management platform.</p>
                    
                    <div style="background-color: #f8f9fa; padding: 25px; border-radius: 10px; margin: 20px 0;">
                        <h3 style="color: #2c5530; margin-top: 0; display: flex; align-items: center;">
                            🚀 Getting Started
                        </h3>
                        <p>Here's what you can do with your %s account:</p>
                        <ul style="list-style-type: none; padding: 0;">
                            <li style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                📋 <strong>Manage Policies:</strong> View, update, and track all your insurance policies
                            </li>
                            <li style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                🎯 <strong>File Claims:</strong> Submit and monitor insurance claims easily
                            </li>
                            <li style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                📊 <strong>Track Status:</strong> Get real-time updates on your policies and claims
                            </li>
                            <li style="margin: 10px 0; padding: 10px; background: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                💬 <strong>24/7 Support:</strong> Access our support team whenever you need help
                            </li>
                        </ul>
                    </div>
                    
                    <div style="background-color: #e3f2fd; padding: 20px; border-left: 4px solid #2196f3; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #1976d2; margin-top: 0;">Account Information</h4>
                        <p><strong>Username:</strong> %s</p>
                        <p><strong>Email:</strong> %s</p>
                        <p><strong>Registration Date:</strong> %s</p>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/dashboard" style="background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);">Access Your Dashboard</a>
                    </div>
                    
                    <div style="background-color: #fff3e0; padding: 20px; border-left: 4px solid #ff9800; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #f57c00; margin-top: 0;">Need Help?</h4>
                        <p>If you have any questions or need assistance getting started, our support team is here to help:</p>
                        <p>📧 Email: <a href="mailto:%s" style="color: #007bff;">%s</a></p>
                        <p>📞 Phone: 1-800-POLICY-360</p>
                        <p>💬 Live Chat: Available 24/7 on our website</p>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Thank you for choosing <strong>%s</strong>. We look forward to serving your insurance needs!<br><br>
                        Best regards,<br>
                        <strong>The %s Team</strong><br>
                        <em>Your trusted insurance management partner</em>
                    </p>
                </div>
            </body>
            </html>
            """,
                appName, // Welcome title
                username, // Dear username
                appName, // family name
                appName, // account features
                username, // account username
                email, // account email
                LocalDateTime.now().format(DATE_FORMATTER), // registration date
                baseUrl, // dashboard link
                supportEmail, // support email link
                supportEmail, // support email display
                appName, // thank you message
                appName // team name
        );
    }

    private String buildPasswordResetEmailContent(String resetToken) {
        String resetLink = baseUrl + "/auth/reset-password?token=" + resetToken;

        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #dc3545;">🔒 Password Reset Request</h2>
                    
                    <p>Hello,</p>
                    
                    <p>We received a request to reset the password for your %s account.</p>
                    
                    <div style="background-color: #fff3cd; padding: 20px; border-left: 4px solid #ffc107; margin: 20px 0;">
                        <h3 style="color: #856404; margin-top: 0;">Security Notice</h3>
                        <p>If you did not request this password reset, please ignore this email. Your password will remain unchanged.</p>
                    </div>
                    
                    <p>To reset your password, click the button below:</p>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s" style="background-color: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
                    </div>
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        If the button doesn't work, copy and paste this link into your browser:<br>
                        <a href="%s" style="color: #007bff;">%s</a>
                    </p>
                    
                    <div style="background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
                        <p style="margin: 0; color: #721c24; font-weight: bold;">⚠️ This link will expire in 24 hours for security reasons.</p>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Best regards,<br>
                        <strong>%s Security Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                appName,
                resetLink,
                resetLink,
                resetLink,
                appName,
                supportEmail
        );
    }

    private String buildAccountActivationEmailContent(String activationLink) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px;">
                        <h1 style="color: #28a745;">✅ Activate Your Account</h1>
                        <p style="color: #6c757d;">Complete your %s registration</p>
                    </div>
                    
                    <p>Hello,</p>
                    
                    <p>Thank you for registering with %s! To complete your account setup, please activate your account by clicking the button below.</p>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Activate Account</a>
                    </div>
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        If the button doesn't work, copy and paste this link into your browser:<br>
                        <a href="%s" style="color: #007bff;">%s</a>
                    </p>
                    
                    <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
                        <p style="margin: 0; color: #856404;">⏰ This activation link will expire in 48 hours.</p>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Welcome to the %s family!<br><br>
                        Best regards,<br>
                        <strong>%s Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                appName,
                appName,
                activationLink,
                activationLink,
                activationLink,
                appName,
                appName,
                supportEmail
        );
    }

    private String buildPolicyCreatedEmailContent(Policy policy) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #28a745 0%%, #20c997 100%%); border-radius: 10px;">
                        <h1 style="color: white; margin: 0;">📋 Policy Created Successfully</h1>
                        <p style="color: #f8f9fa; margin: 10px 0;">Your coverage is now active</p>
                    </div>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>Congratulations! Your new insurance policy has been successfully created and is now <strong style="color: #28a745;">ACTIVE</strong>.</p>
                    
                    <div style="background-color: #d4edda; padding: 25px; border-left: 4px solid #28a745; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #155724; margin-top: 0;">Policy Summary</h3>
                        <div style="display: grid; gap: 10px;">
                            <p><strong>Policy Number:</strong> <span style="color: #007bff; font-weight: bold;">%s</span></p>
                            <p><strong>Policy Type:</strong> %s</p>
                            <p><strong>Coverage Amount:</strong> <span style="color: #28a745; font-size: 18px; font-weight: bold;">$%,.2f</span></p>
                            <p><strong>Monthly Premium:</strong> $%,.2f</p>
                            <p><strong>Policy Period:</strong> %s to %s</p>
                            <p><strong>Status:</strong> <span style="color: #28a745; font-weight: bold;">%s</span></p>
                        </div>
                    </div>
                    
                    <div style="background-color: #cce7ff; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #004085; margin-top: 0;">What's Next?</h4>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>Your policy is immediately effective</li>
                            <li>You can file claims starting now</li>
                            <li>Policy documents will be available in your dashboard</li>
                            <li>Premium payments are due monthly on the 1st</li>
                        </ul>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/policy/%d" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; margin-right: 10px;">View Policy</a>
                        <a href="%s/dashboard" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Go to Dashboard</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Thank you for choosing <strong>%s</strong> for your insurance needs.<br><br>
                        Best regards,<br>
                        <strong>%s Policy Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                policy.getCustomer().getFullName(),
                policy.getPolicyNumber(),
                policy.getPolicyType().getDescription(),
                policy.getCoverageAmount(),
                policy.getPremiumAmount(),
                policy.getStartDate().format(DATE_FORMATTER),
                policy.getEndDate().format(DATE_FORMATTER),
                policy.getStatus().name(),
                baseUrl,
                policy.getId(),
                baseUrl,
                appName,
                appName,
                supportEmail
        );
    }

    private String buildPolicyExpirationReminderContent(Policy policy, int daysUntilExpiry) {
        String urgencyColor = daysUntilExpiry <= 7 ? "#dc3545" : "#ffc107";
        String urgencyMessage = daysUntilExpiry <= 7 ? "⚠️ URGENT" : "⏰ REMINDER";

        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px; padding: 20px; background-color: %s; border-radius: 10px;">
                        <h1 style="color: white; margin: 0;">%s</h1>
                        <h2 style="color: white; margin: 10px 0;">Policy Expiration Notice</h2>
                    </div>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>This is an important reminder that your insurance policy will expire in <strong style="color: %s;">%d days</strong>.</p>
                    
                    <div style="background-color: #fff3cd; padding: 25px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #856404; margin-top: 0;">Policy Information</h3>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Policy Type:</strong> %s</p>
                        <p><strong>Expiration Date:</strong> <span style="color: %s; font-weight: bold;">%s</span></p>
                        <p><strong>Coverage Amount:</strong> $%,.2f</p>
                        <p><strong>Days Remaining:</strong> <span style="color: %s; font-size: 18px; font-weight: bold;">%d days</span></p>
                    </div>
                    
                    <div style="background-color: #e3f2fd; padding: 20px; border-left: 4px solid #2196f3; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #1976d2; margin-top: 0;">Renewal Options</h4>
                        <p>Don't let your coverage lapse! Here are your options:</p>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li><strong>Auto-Renewal:</strong> Continue with the same coverage</li>
                            <li><strong>Update Policy:</strong> Modify coverage amounts or terms</li>
                            <li><strong>New Policy:</strong> Explore different policy types</li>
                            <li><strong>Contact Agent:</strong> Speak with our insurance experts</li>
                        </ul>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/policy/%d/renew" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; margin-right: 10px;">Renew Now</a>
                        <a href="mailto:%s" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Contact Agent</a>
                    </div>
                    
                    %s
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Don't risk being without coverage. Act today to ensure continuous protection.<br><br>
                        Best regards,<br>
                        <strong>%s Policy Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                urgencyColor,
                urgencyMessage,
                policy.getCustomer().getFullName(),
                urgencyColor,
                daysUntilExpiry,
                policy.getPolicyNumber(),
                policy.getPolicyType().getDescription(),
                urgencyColor,
                policy.getEndDate().format(DATE_FORMATTER),
                policy.getCoverageAmount(),
                urgencyColor,
                daysUntilExpiry,
                baseUrl,
                policy.getId(),
                supportEmail,
                daysUntilExpiry <= 7 ?
                        "<div style=\"background-color: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0; border-radius: 5px;\"><p style=\"margin: 0; color: #721c24; font-weight: bold;\">🚨 IMPORTANT: Your policy will expire very soon! Immediate action required to avoid coverage gaps.</p></div>" :
                        "<div style=\"background-color: #d1ecf1; padding: 15px; border-left: 4px solid #bee5eb; margin: 20px 0; border-radius: 5px;\"><p style=\"margin: 0; color: #0c5460;\">💡 <strong>Tip:</strong> Renewing early ensures no gap in coverage and may qualify you for loyalty discounts.</p></div>",
                appName,
                supportEmail
        );
    }

    private String buildPolicyRenewalEmailContent(Policy policy) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <div style="text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #28a745 0%%, #20c997 100%%); border-radius: 10px;">
                        <h1 style="color: white; margin: 0;">🎉 Policy Renewed Successfully</h1>
                        <p style="color: #f8f9fa; margin: 10px 0;">Your coverage continues without interruption</p>
                    </div>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>Great news! Your insurance policy has been successfully renewed. Your continuous coverage ensures you remain protected.</p>
                    
                    <div style="background-color: #d4edda; padding: 25px; border-left: 4px solid #28a745; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #155724; margin-top: 0;">Renewed Policy Details</h3>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Policy Type:</strong> %s</p>
                        <p><strong>New Coverage Period:</strong> %s to %s</p>
                        <p><strong>Coverage Amount:</strong> $%,.2f</p>
                        <p><strong>Monthly Premium:</strong> $%,.2f</p>
                        <p><strong>Renewal Date:</strong> %s</p>
                    </div>
                    
                    <div style="background-color: #cce7ff; padding: 20px; border-left: 4px solid #007bff; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #004085; margin-top: 0;">What This Means</h4>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>No gap in coverage - you're continuously protected</li>
                            <li>Updated policy documents are now available</li>
                            <li>Previous policy terms and conditions carry forward</li>
                            <li>Next premium payment due on the 1st of next month</li>
                        </ul>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/policy/%d" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">View Renewed Policy</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        Thank you for continuing to trust <strong>%s</strong> with your insurance needs.<br><br>
                        Best regards,<br>
                        <strong>%s Policy Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                policy.getCustomer().getFullName(),
                policy.getPolicyNumber(),
                policy.getPolicyType().getDescription(),
                policy.getStartDate().format(DATE_FORMATTER),
                policy.getEndDate().format(DATE_FORMATTER),
                policy.getCoverageAmount(),
                policy.getPremiumAmount(),
                LocalDateTime.now().format(DATE_FORMATTER),
                baseUrl,
                policy.getId(),
                appName,
                appName,
                supportEmail
        );
    }

    private String buildPolicyCancellationEmailContent(Policy policy, String reason) {
        return String.format("""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #dc3545;">Policy Cancellation Notice</h2>
                    
                    <p>Dear <strong>%s</strong>,</p>
                    
                    <p>We are writing to confirm that your insurance policy has been cancelled as requested.</p>
                    
                    <div style="background-color: #f8d7da; padding: 25px; border-left: 4px solid #dc3545; margin: 20px 0; border-radius: 5px;">
                        <h3 style="color: #721c24; margin-top: 0;">Cancelled Policy Details</h3>
                        <p><strong>Policy Number:</strong> %s</p>
                        <p><strong>Policy Type:</strong> %s</p>
                        <p><strong>Cancellation Date:</strong> %s</p>
                        <p><strong>Final Coverage Date:</strong> %s</p>
                        <p><strong>Reason:</strong> %s</p>
                    </div>
                    
                    <div style="background-color: #fff3cd; padding: 20px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #856404; margin-top: 0;">Important Information</h4>
                        <ul style="margin: 10px 0; padding-left: 20px;">
                            <li>Coverage ends on the date specified above</li>
                            <li>Any pending claims will be processed according to policy terms</li>
                            <li>Refund calculations (if applicable) will be processed within 5-10 business days</li>
                            <li>You can reapply for coverage at any time in the future</li>
                        </ul>
                    </div>
                    
                    <div style="background-color: #e3f2fd; padding: 20px; border-left: 4px solid #2196f3; margin: 20px 0; border-radius: 5px;">
                        <h4 style="color: #1976d2; margin-top: 0;">We're Here to Help</h4>
                        <p>If you have any questions about your cancellation or would like to explore other coverage options, please don't hesitate to contact us.</p>
                        <p><strong>Contact Options:</strong></p>
                        <p>📧 Email: <a href="mailto:%s" style="color: #007bff;">%s</a></p>
                        <p>📞 Phone: 1-800-POLICY-360</p>
                    </div>
                    
                    <div style="margin: 30px 0; text-align: center;">
                        <a href="%s/policies/new" style="background-color: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; margin-right: 10px;">Get New Quote</a>
                        <a href="mailto:%s" style="background-color: #007bff; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Contact Support</a>
                    </div>
                    
                    <hr style="border: none; height: 1px; background-color: #dee2e6; margin: 30px 0;">
                    
                    <p style="color: #6c757d; font-size: 14px;">
                        We're sorry to see you go and hope to serve you again in the future.<br><br>
                        Best regards,<br>
                        <strong>%s Policy Team</strong><br>
                        Email: %s
                    </p>
                </div>
            </body>
            </html>
            """,
                policy.getCustomer().getFullName(),
                policy.getPolicyNumber(),
                policy.getPolicyType().getDescription(),
                LocalDateTime.now().format(DATE_FORMATTER),
                policy.getEndDate().format(DATE_FORMATTER),
                reason != null ? reason : "Customer requested cancellation",
                supportEmail,
                supportEmail,
                baseUrl,
                supportEmail,
                appName,
                supportEmail
        );
    }

    // UTILITY METHODS

    private String getStatusColor(ClaimStatus status) {
        return switch (status) {
            case APPROVED -> "#28a745";
            case REJECTED -> "#dc3545";
            case PROCESSING -> "#ffc107";
            case PENDING -> "#6c757d";
            default -> "#007bff";
        };
    }

    private String getStatusMessage(ClaimStatus status) {
        return switch (status) {
            case APPROVED -> "<p style=\"color: #28a745; font-weight: bold;\">🎉 Congratulations! Your claim has been approved and payment processing will begin shortly.</p>";
            case REJECTED -> "<p style=\"color: #dc3545; font-weight: bold;\">❌ Unfortunately, your claim was not approved. Please review the details or contact our support team if you have questions.</p>";
            case PROCESSING -> "<p style=\"color: #ffc107; font-weight: bold;\">⏳ Your claim is currently being processed. We'll update you once a decision is made.</p>";
            case PENDING -> "<p style=\"color: #6c757d; font-weight: bold;\">📋 Your claim is pending review. We may contact you if additional information is needed.</p>";
            default -> "<p>Your claim status has been updated. Please check your dashboard for more details.</p>";
        };
    }
}
