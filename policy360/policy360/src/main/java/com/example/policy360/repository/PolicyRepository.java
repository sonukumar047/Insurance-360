package com.example.policy360.repository;

import com.example.policy360.entity.Policy;
import com.example.policy360.entity.enums.PolicyStatus;
import com.example.policy360.entity.enums.PolicyType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long>, JpaSpecificationExecutor<Policy> {

    // Basic queries
    Optional<Policy> findByPolicyNumber(String policyNumber);
    boolean existsByPolicyNumber(String policyNumber);

    // Customer-related queries
    List<Policy> findByCustomerId(Long customerId);

    @Query("SELECT p FROM Policy p WHERE p.customer.id = :customerId")
    Page<Policy> findByCustomerId(@Param("customerId") Long customerId, Pageable pageable);

    @Query("SELECT COUNT(p) FROM Policy p WHERE p.customer.id = :customerId AND p.status = :status")
    long countByCustomerIdAndStatus(@Param("customerId") Long customerId, @Param("status") PolicyStatus status);

    // Status-related queries
    List<Policy> findByStatus(PolicyStatus status);
    Page<Policy> findByStatus(PolicyStatus status, Pageable pageable);

    // Type-related queries
    List<Policy> findByPolicyType(PolicyType policyType);
    boolean existsByCustomerIdAndPolicyTypeAndStatus(Long customerId, PolicyType policyType, PolicyStatus status);

    // Date-related queries
    List<Policy> findByEndDateBeforeAndStatus(LocalDate endDate, PolicyStatus status);
    List<Policy> findByEndDateBetweenAndStatus(LocalDate startDate, LocalDate endDate, PolicyStatus status);
    List<Policy> findByRenewalDateBeforeAndStatus(LocalDate renewalDate, PolicyStatus status);

    @Query("SELECT p FROM Policy p WHERE p.endDate BETWEEN :startDate AND :endDate AND p.status = 'ACTIVE'")
    List<Policy> findExpiringPolicies(@Param("startDate") LocalDate startDate, @Param("endDate") LocalDate endDate);

    // Premium-related queries
    List<Policy> findByPremiumAmountBetween(BigDecimal minAmount, BigDecimal maxAmount);

    @Query("SELECT SUM(p.premiumAmount) FROM Policy p WHERE p.customer.id = :customerId AND p.status = :status")
    BigDecimal getTotalPremiumByCustomerAndStatus(@Param("customerId") Long customerId, @Param("status") PolicyStatus status);

    // Complex business queries
    @Query("SELECT p FROM Policy p WHERE p.status = 'ACTIVE' AND p.endDate <= :date")
    List<Policy> findPoliciesNearExpiry(@Param("date") LocalDate date);

    @Query("SELECT p FROM Policy p WHERE p.renewalDate <= :date AND p.status = 'ACTIVE'")
    List<Policy> findPoliciesEligibleForRenewal(@Param("date") LocalDate date);

    @Query("SELECT p.policyType, COUNT(p) FROM Policy p WHERE p.status = :status GROUP BY p.policyType")
    List<Object[]> countPoliciesByTypeAndStatus(@Param("status") PolicyStatus status);

    @Query("SELECT p FROM Policy p WHERE p.customer.id = :customerId AND p.status = :status")
    List<Policy> findByCustomerIdAndStatus(@Param("customerId") Long customerId, @Param("status") PolicyStatus status);

    // Statistics queries
    @Query("SELECT COUNT(p) FROM Policy p WHERE p.createdAt >= :startDate AND p.createdAt <= :endDate")
    long countPoliciesCreatedBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    @Query("SELECT AVG(p.premiumAmount) FROM Policy p WHERE p.policyType = :policyType AND p.status = 'ACTIVE'")
    BigDecimal getAveragePremiumByPolicyType(@Param("policyType") PolicyType policyType);

    @Query("SELECT p FROM Policy p JOIN p.claims c WHERE c.status = 'APPROVED' GROUP BY p HAVING COUNT(c) >= :minClaims")
    List<Policy> findPoliciesWithMultipleClaims(@Param("minClaims") long minClaims);

    // Advanced search queries
    @Query("SELECT p FROM Policy p WHERE " +
            "(:policyNumber IS NULL OR LOWER(p.policyNumber) LIKE LOWER(CONCAT('%', :policyNumber, '%'))) AND " +
            "(:policyType IS NULL OR p.policyType = :policyType) AND " +
            "(:status IS NULL OR p.status = :status) AND " +
            "(:customerId IS NULL OR p.customer.id = :customerId)")
    Page<Policy> searchPolicies(@Param("policyNumber") String policyNumber,
                                @Param("policyType") PolicyType policyType,
                                @Param("status") PolicyStatus status,
                                @Param("customerId") Long customerId,
                                Pageable pageable);
}
