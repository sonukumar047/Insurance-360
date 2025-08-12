package com.example.policy360.config;

import org.springframework.boot.actuate.autoconfigure.endpoint.condition.ConditionalOnAvailableEndpoint;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ActuatorConfig {

    @Bean
//    @ConditionalOnAvailableEndpoint
    public HealthIndicator customHealthIndicator() {
        return () -> Health.up()
                .withDetail("app", "Policy360")
                .withDetail("status", "Running")
                .withDetail("version", "1.0.0")
                .build();
    }

}
