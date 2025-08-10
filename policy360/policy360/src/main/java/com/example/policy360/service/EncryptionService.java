package com.example.policy360.service;

public interface EncryptionService {
    String encrypt(String data);
    String decrypt(String encryptedData);
}
