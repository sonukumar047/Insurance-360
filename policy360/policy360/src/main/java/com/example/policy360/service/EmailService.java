package com.example.policy360.service;

import com.example.policy360.entity.Claim;

public interface EmailService {
    void sendClaimReminderEmail(Claim claim);
    void sendWelcomeEmail(String email, String username);
    void sendClaimStatusUpdateEmail(Claim claim);
}
