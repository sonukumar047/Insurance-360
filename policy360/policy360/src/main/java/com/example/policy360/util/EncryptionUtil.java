package com.example.policy360.util;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

//@Component
//@Converter
//public class EncryptionUtil implements AttributeConverter<String, String> {
//
//    private static final String ALGORITHM = "AES";
//    private static final String TRANSFORMATION = "AES";
//
//    @Value("${encryption.secret-key}")
//    private String secretKey;
//
//    @Override
//    public String convertToDatabaseColumn(String attribute) {
//        if (attribute == null) {
//            return null;
//        }
//        try {
//            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//            cipher.init(Cipher.ENCRYPT_MODE, key);
//            return Base64.getEncoder().encodeToString(cipher.doFinal(attribute.getBytes()));
//        } catch (Exception e) {
//            throw new RuntimeException("Error encrypting data", e);
//        }
//    }
//
//    @Override
//    public String convertToEntityAttribute(String dbData) {
//        if (dbData == null) {
//            return null;
//        }
//        try {
//            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
//            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
//            cipher.init(Cipher.DECRYPT_MODE, key);
//            return new String(cipher.doFinal(Base64.getDecoder().decode(dbData)));
//        } catch (Exception e) {
//            throw new RuntimeException("Error decrypting data", e);
//        }
//    }
//}


@Component
@Converter
public class EncryptionUtil implements AttributeConverter<String, String> {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    @Value("${encryption.secret-key}")
    private String secretKey;

    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null || attribute.trim().isEmpty()) {
            return attribute;
        }
        try {
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(attribute.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return dbData;
        }

        // Check if data is already encrypted (Base64 format)
        if (!isBase64(dbData)) {
            // Data is not encrypted, return as-is (for migration scenarios)
            return dbData;
        }

        try {
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(dbData)));
        } catch (Exception e) {
            // If decryption fails, assume it's unencrypted data
            return dbData;
        }
    }

    private boolean isBase64(String str) {
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
