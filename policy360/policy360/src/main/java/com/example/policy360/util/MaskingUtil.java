package com.example.policy360.util;

public class MaskingUtil {

    public static String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }
        String[] parts = email.split("@");
        String username = parts[0];
        String domain = parts[1];

        if (username.length() <= 2) {
            return "*".repeat(username.length()) + "@" + domain;
        }

        return username.charAt(0) + "*".repeat(username.length() - 2) +
                username.charAt(username.length() - 1) + "@" + domain;
    }

    public static String maskMobile(String mobile) {
        if (mobile == null || mobile.length() < 4) {
            return mobile;
        }
        return "*".repeat(mobile.length() - 4) + mobile.substring(mobile.length() - 4);
    }

    public static String maskName(String name) {
        if (name == null || name.length() <= 2) {
            return name;
        }
        return name.charAt(0) + "*".repeat(name.length() - 2) + name.charAt(name.length() - 1);
    }
}
