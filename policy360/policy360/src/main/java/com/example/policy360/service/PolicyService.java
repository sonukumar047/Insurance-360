package com.example.policy360.service;

import com.example.policy360.dto.PolicyDto;

import java.util.List;

public interface PolicyService {
    PolicyDto getPolicyById(Long id);
    List<PolicyDto> getAllPolicies();
    PolicyDto createPolicy(PolicyDto policyDto);
    PolicyDto updatePolicy(Long id, PolicyDto policyDto);
    void deletePolicy(Long id);
    List<PolicyDto> getPoliciesByCustomerId(Long customerId);
}
