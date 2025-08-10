package com.example.policy360.aspect;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.policy360.entity.AuditLog;
import com.example.policy360.service.AuditService;
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

    @AfterReturning(pointcut = "execution(* com.policy360.controller.*.*(..)) && " +
            "(execution(* com.policy360.controller.*.*Post*(..)) || " +
            "execution(* com.policy360.controller.*.*Put*(..)))",
            returning = "result")
    public void auditPostAndPutOperations(JoinPoint joinPoint, Object result) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            HttpServletRequest request = ((ServletRequestAttributes)
                    RequestContextHolder.currentRequestAttributes()).getRequest();

            AuditLog auditLog = new AuditLog();
            auditLog.setUsername(authentication != null ? authentication.getName() : "anonymous");
            auditLog.setAction(joinPoint.getSignature().getName());
            auditLog.setEntityType(joinPoint.getTarget().getClass().getSimpleName());
            auditLog.setIpAddress(getClientIpAddress(request));

            Object[] args = joinPoint.getArgs();
            if (args != null && args.length > 0) {
                auditLog.setDetails("Arguments: " + objectMapper.writeValueAsString(args));
            }

            auditService.saveAuditLog(auditLog);
            log.info("Audit log created for action: {}", joinPoint.getSignature().getName());

        } catch (Exception e) {
            log.error("Error creating audit log", e);
        }
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null) {
            return request.getRemoteAddr();
        } else {
            return xForwardedForHeader.split(",")[0];
        }
    }
}
