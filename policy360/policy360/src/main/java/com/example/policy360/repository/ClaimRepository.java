// src/main/java/com/example/policy360/repository/ClaimRepository.java
package com.example.policy360.repository;

import com.example.policy360.entity.Claim;
import com.example.policy360.entity.enums.ClaimStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ClaimRepository extends JpaRepository<Claim, Long> {
    List<Claim> findByPolicyId(Long policyId);
    List<Claim> findByStatus(ClaimStatus status);
    Optional<Claim> findByClaimNumber(String claimNumber);

    // Corrected query for MySQL - DATEDIFF takes only 2 parameters
    @Query("SELECT c FROM Claim c WHERE c.status = 'PENDING' AND " +
            "DATEDIFF(CURRENT_DATE, c.submittedDate) >= 7")
    List<Claim> findPendingClaimsOlderThanWeek();
}
