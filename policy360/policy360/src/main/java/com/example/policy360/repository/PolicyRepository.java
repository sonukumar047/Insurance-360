package com.example.policy360.repository;

import com.example.policy360.entity.Policy;
import com.example.policy360.entity.enums.PolicyStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long> {
    List<Policy> findByCustomerId(Long customerId);
    List<Policy> findByStatus(PolicyStatus status);
    boolean existsByPolicyNumber(String policyNumber);
    Optional<Policy> findByPolicyNumber(String policyNumber);
}
