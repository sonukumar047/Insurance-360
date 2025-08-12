package com.example.policy360.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "policy360.masking")
@Data
public class MaskingConfig {

    private boolean enabled = true;
    private boolean emailEnabled = true;
    private boolean phoneEnabled = true;
    private boolean financialEnabled = true;
    private boolean addressEnabled = true;
    private boolean policyNumberEnabled = false;
    private boolean claimNumberEnabled = false;

    // Role-based permissions
    private boolean adminExempt = true;
    private boolean agentFinancialMask = true;
    private boolean customerFullMask = true;
}
