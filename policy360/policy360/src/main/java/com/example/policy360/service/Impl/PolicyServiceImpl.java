package com.example.policy360.service.Impl;

import com.example.policy360.dto.PolicyDto;
import com.example.policy360.entity.Policy;
import com.example.policy360.entity.User;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.exception.PolicyNotFoundException;
import com.example.policy360.exception.UserNotFoundException;
import com.example.policy360.repository.PolicyRepository;
import com.example.policy360.repository.UserRepository;
import com.example.policy360.service.PolicyService;
import com.example.policy360.util.MaskingUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class PolicyServiceImpl implements PolicyService {

    private final PolicyRepository policyRepository;
    private final UserRepository userRepository;

    @Override
    public PolicyDto getPolicyById(Long id) {
        log.info("Fetching policy with ID: {}", id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        return convertToMaskedDto(policy);
    }

    @Override
    public List<PolicyDto> getAllPolicies() {
        log.info("Fetching all policies");

        List<Policy> policies = policyRepository.findAll();
        return policies.stream()
                .map(this::convertToMaskedDto)
                .collect(Collectors.toList());
    }

    @Override
    public PolicyDto createPolicy(PolicyDto policyDto) {
        log.info("Creating new policy for customer ID: {}", policyDto.getCustomerId());

        User customer = userRepository.findById(policyDto.getCustomerId())
                .orElseThrow(() -> new UserNotFoundException("Customer not found with ID: " + policyDto.getCustomerId()));

        Policy policy = convertToEntity(policyDto);
        policy.setCustomer(customer);
        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setCreatedAt(LocalDateTime.now());
        policy.setUpdatedAt(LocalDateTime.now());

        Policy savedPolicy = policyRepository.save(policy);
        log.info("Policy created successfully with ID: {}", savedPolicy.getId());

        return convertToMaskedDto(savedPolicy);
    }

    @Override
    public PolicyDto updatePolicy(Long id, PolicyDto policyDto) {
        log.info("Updating policy with ID: {}", id);

        Policy existingPolicy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        updatePolicyFields(existingPolicy, policyDto);
        existingPolicy.setUpdatedAt(LocalDateTime.now());

        Policy updatedPolicy = policyRepository.save(existingPolicy);
        log.info("Policy updated successfully with ID: {}", updatedPolicy.getId());

        return convertToMaskedDto(updatedPolicy);
    }

    @Override
    public void deletePolicy(Long id) {
        log.info("Deleting policy with ID: {}", id);

        Policy policy = policyRepository.findById(id)
                .orElseThrow(() -> new PolicyNotFoundException("Policy not found with ID: " + id));

        policyRepository.delete(policy);
        log.info("Policy deleted successfully with ID: {}", id);
    }

    @Override
    public List<PolicyDto> getPoliciesByCustomerId(Long customerId) {
        log.info("Fetching policies for customer ID: {}", customerId);

        List<Policy> policies = policyRepository.findByCustomerId(customerId);
        return policies.stream()
                .map(this::convertToMaskedDto)
                .collect(Collectors.toList());
    }

    private PolicyDto convertToMaskedDto(Policy policy) {
        PolicyDto dto = new PolicyDto();
        dto.setId(policy.getId());
        dto.setPolicyNumber(policy.getPolicyNumber());
        dto.setCustomerId(policy.getCustomer().getId());
        dto.setCustomerName(MaskingUtil.maskName(policy.getCustomer().getFullName()));
        dto.setCustomerEmail(MaskingUtil.maskEmail(policy.getCustomer().getEmail()));
        dto.setCustomerMobile(MaskingUtil.maskMobile(policy.getCustomer().getMobileNumber()));
        dto.setPolicyType(policy.getPolicyType());
        dto.setPremiumAmount(policy.getPremiumAmount());
        dto.setCoverageAmount(policy.getCoverageAmount());
        dto.setStartDate(policy.getStartDate());
        dto.setEndDate(policy.getEndDate());
        dto.setStatus(policy.getStatus().name());
        return dto;
    }

    private Policy convertToEntity(PolicyDto dto) {
        Policy policy = new Policy();
        policy.setPolicyNumber(dto.getPolicyNumber());
        policy.setPolicyType(dto.getPolicyType());
        policy.setPremiumAmount(dto.getPremiumAmount());
        policy.setCoverageAmount(dto.getCoverageAmount());
        policy.setStartDate(dto.getStartDate());
        policy.setEndDate(dto.getEndDate());
        return policy;
    }

    private void updatePolicyFields(Policy policy, PolicyDto dto) {
        if (dto.getPolicyType() != null) {
            policy.setPolicyType(dto.getPolicyType());
        }
        if (dto.getPremiumAmount() != null) {
            policy.setPremiumAmount(dto.getPremiumAmount());
        }
        if (dto.getCoverageAmount() != null) {
            policy.setCoverageAmount(dto.getCoverageAmount());
        }
        if (dto.getStartDate() != null) {
            policy.setStartDate(dto.getStartDate());
        }
        if (dto.getEndDate() != null) {
            policy.setEndDate(dto.getEndDate());
        }
        if (dto.getStatus() != null) {
            policy.setStatus(PolicyStatus.valueOf(dto.getStatus()));
        }
    }
}
