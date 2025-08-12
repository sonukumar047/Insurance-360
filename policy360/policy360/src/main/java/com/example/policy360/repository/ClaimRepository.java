package com.example.policy360.repository;

import com.example.policy360.entity.Claim;
import com.example.policy360.entity.enums.ClaimStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ClaimRepository extends JpaRepository<Claim, Long>, JpaSpecificationExecutor<Claim> {

    Optional<Claim> findByClaimNumber(String claimNumber);
    List<Claim> findByPolicyId(Long policyId);
    List<Claim> findByStatus(ClaimStatus status);
    Page<Claim> findByStatus(ClaimStatus status, Pageable pageable);

    @Query("SELECT c FROM Claim c WHERE c.policy.customer.id = :customerId")
    List<Claim> findByCustomerId(@Param("customerId") Long customerId);

    @Query("SELECT c FROM Claim c WHERE c.policy.customer.id = :customerId")
    Page<Claim> findByCustomerId(@Param("customerId") Long customerId, Pageable pageable);

    List<Claim> findByStatusAndSubmittedDateBefore(ClaimStatus status, LocalDateTime dateTime);

    @Query("SELECT COUNT(c) FROM Claim c WHERE c.policy.id = :policyId AND c.status = :status")
    long countByPolicyIdAndStatus(@Param("policyId") Long policyId, @Param("status") ClaimStatus status);

    boolean existsByPolicyId(Long policyId);
    boolean existsByClaimNumber(String claimNumber);

    @Query("SELECT c FROM Claim c WHERE c.submittedDate BETWEEN :startDate AND :endDate")
    List<Claim> findBySubmittedDateBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
}

