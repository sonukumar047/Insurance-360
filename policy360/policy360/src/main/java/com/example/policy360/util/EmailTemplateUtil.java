package com.example.policy360.util;

import org.springframework.stereotype.Component;

@Component
public class EmailTemplateUtil {

    public String processTemplate(String templateName, Object data) {
        // Basic template processing - can be enhanced with Thymeleaf or Freemarker
        // For now, return a simple placeholder
        return "<html><body><h2>Template: " + templateName + "</h2><p>Data: " + data.toString() + "</p></body></html>";
    }
}
