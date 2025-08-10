package com.example.policy360.service.Impl;

import com.example.policy360.entity.AuditLog;
import com.example.policy360.repository.AuditLogRepository;
import com.example.policy360.service.AuditService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditServiceImpl implements AuditService {

    private final AuditLogRepository auditLogRepository;

    @Override
    public void saveAuditLog(AuditLog auditLog) {
        log.debug("Saving audit log for user: {}, action: {}", auditLog.getUsername(), auditLog.getAction());
        auditLogRepository.save(auditLog);
    }

    @Override
    public Page<AuditLog> getAllAuditLogs(Pageable pageable) {
        log.info("Fetching all audit logs with page: {}, size: {}", pageable.getPageNumber(), pageable.getPageSize());
        return auditLogRepository.findAll(pageable);
    }

    @Override
    public Page<AuditLog> getAuditLogsByUsername(String username, Pageable pageable) {
        log.info("Fetching audit logs for username: {} with page: {}, size: {}", username, pageable.getPageNumber(), pageable.getPageSize());
        return auditLogRepository.findByUsernameOrderByTimestampDesc(username, pageable);
    }

    @Override
    public Page<AuditLog> getAuditLogsByDateRange(LocalDateTime start, LocalDateTime end, Pageable pageable) {
        log.info("Fetching audit logs between {} and {} with page: {}, size: {}", start, end, pageable.getPageNumber(), pageable.getPageSize());
        return auditLogRepository.findByTimestampBetweenOrderByTimestampDesc(start, end, pageable);
    }
}
