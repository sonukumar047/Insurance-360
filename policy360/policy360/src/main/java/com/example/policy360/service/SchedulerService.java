package com.example.policy360.service;

import com.example.policy360.dto.JobExecutionResult;
import com.example.policy360.dto.SchedulerStatusDto;

import java.util.List;

public interface SchedulerService {
    // Policy-related scheduling
    JobExecutionResult sendExpirationReminders();
    JobExecutionResult sendRenewalReminders();
    JobExecutionResult processExpiredPolicies();
    JobExecutionResult generatePolicyReports();

    // Claim-related scheduling
    JobExecutionResult sendPendingClaimReminders();
    JobExecutionResult processOverdueClaims();
    JobExecutionResult generateClaimReports();

    // System maintenance
    JobExecutionResult performHealthChecks();
    JobExecutionResult archiveOldRecords();
    JobExecutionResult generateSystemReports();

    // Premium and business operations
    JobExecutionResult processAutoRenewals();
    JobExecutionResult sendPaymentReminders();

    // Monitoring and management
    SchedulerStatusDto getSchedulerStatus();
    List<JobExecutionResult> getJobHistory(String jobName, int limit);
    boolean isJobRunning(String jobName);
    JobExecutionResult executeJobManually(String jobName);
}
