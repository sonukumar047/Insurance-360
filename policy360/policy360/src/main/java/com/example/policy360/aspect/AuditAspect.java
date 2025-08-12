// src/main/java/com/example/policy360/aspect/AuditAspect.java
package com.example.policy360.aspect;

import com.example.policy360.service.AuditService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditAspect {

    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.PolicyServiceImpl.createPolicy(..))", returning = "result")
    public void auditPolicyCreation(JoinPoint joinPoint, Object result) {
        saveAuditLog("CREATE", "Policy", result, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.PolicyServiceImpl.updatePolicy(..))", returning = "result")
    public void auditPolicyUpdate(JoinPoint joinPoint, Object result) {
        saveAuditLog("UPDATE", "Policy", result, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.PolicyServiceImpl.deletePolicy(..))")
    public void auditPolicyDeletion(JoinPoint joinPoint) {
        saveAuditLog("DELETE", "Policy", null, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.ClaimServiceImpl.createClaim(..))", returning = "result")
    public void auditClaimCreation(JoinPoint joinPoint, Object result) {
        saveAuditLog("CREATE", "Claim", result, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.ClaimServiceImpl.updateClaimStatus(..))", returning = "result")
    public void auditClaimStatusUpdate(JoinPoint joinPoint, Object result) {
        saveAuditLog("UPDATE_STATUS", "Claim", result, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.AuthServiceImpl.register(..))", returning = "result")
    public void auditUserRegistration(JoinPoint joinPoint, Object result) {
        saveAuditLog("REGISTER", "User", result, joinPoint.getArgs());
    }

    @AfterReturning(value = "execution(* com.example.policy360.service.Impl.AuthServiceImpl.login(..))", returning = "result")
    public void auditUserLogin(JoinPoint joinPoint, Object result) {
        saveAuditLog("LOGIN", "User", result, joinPoint.getArgs());
    }

    private void saveAuditLog(String action, String entityType, Object result, Object[] args) {
        try {
            String username = getCurrentUsername();
            String ipAddress = getClientIpAddress();
            String entityId = extractEntityId(result);
            String details = createDetails(action, args, result);

            auditService.saveAuditLog(username, action, entityType, entityId, details, ipAddress);
        } catch (Exception e) {
            log.error("Error saving audit log: {}", e.getMessage());
        }
    }

    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "SYSTEM";
    }

    private String getClientIpAddress() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        }
        return "unknown";
    }

    private String extractEntityId(Object result) {
        if (result == null) return null;
        try {
            // Assuming your DTOs have an 'id' field
            return objectMapper.writeValueAsString(result).contains("\"id\"")
                    ? objectMapper.readTree(objectMapper.writeValueAsString(result)).get("id").asText()
                    : "N/A";
        } catch (Exception e) {
            return "N/A";
        }
    }

    private String createDetails(String action, Object[] args, Object result) {
        try {
            return String.format("Action: %s, Input: %s, Result: %s",
                    action,
                    args.length > 0 ? objectMapper.writeValueAsString(args[0]) : "N/A",
                    result != null ? objectMapper.writeValueAsString(result) : "N/A");
        } catch (Exception e) {
            return String.format("Action: %s", action);
        }
    }
}
