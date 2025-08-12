package com.example.policy360.service;

import com.example.policy360.entity.Claim;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.dto.EmailDto;

import java.util.List;

public interface EmailService {
    // Claim-related emails
    void sendClaimReminderEmail(Claim claim);
    void sendClaimStatusUpdateEmail(Claim claim);
    void sendClaimApprovalEmail(Claim claim);
    void sendClaimRejectionEmail(Claim claim, String reason);

    // User-related emails
    void sendWelcomeEmail(String email, String username);
    void sendPasswordResetEmail(String email, String resetToken);
    void sendAccountActivationEmail(String email, String activationLink);

    // Policy-related emails
    void sendPolicyCreatedEmail(Policy policy);
    void sendPolicyExpirationReminderEmail(Policy policy, int daysUntilExpiry);
    void sendPolicyRenewalEmail(Policy policy);
    void sendPolicyCancellationEmail(Policy policy, String reason);

    // Batch email operations
    void sendBulkEmails(List<EmailDto> emails);
    void sendClaimReminders(List<Claim> pendingClaims);
    void sendExpirationReminders(List<Policy> expiringPolicies);

    // Template-based email
    void sendTemplateEmail(String to, String subject, String templateName, Object data);

    // Validation
    boolean isValidEmail(String email);
}
