package com.example.policy360.service;

import com.example.policy360.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;

public interface AuditService {
    void saveAuditLog(String username, String action, String entityType, String entityId, String details, String ipAddress);
    Page<AuditLog> getAllAuditLogs(Pageable pageable);
    Page<AuditLog> getAuditLogsByUsername(String username, Pageable pageable);
    Page<AuditLog> getAuditLogsByDateRange(LocalDateTime start, LocalDateTime end, Pageable pageable);
}
