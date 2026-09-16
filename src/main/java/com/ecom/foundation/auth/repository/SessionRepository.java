package com.ecom.foundation.auth.repository;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.ecom.foundation.auth.entity.AuthenticationSession;

public interface SessionRepository extends JpaRepository<AuthenticationSession, Long> {
    Optional<AuthenticationSession> findBySecretHash(String secretHash);

    Optional<AuthenticationSession> findByAccountId(Long accountId);

    Optional<AuthenticationSession> findByIdAndRevokedAtIsNull(Long id);

    @Modifying 
    @Query("""
        UPDATE AuthenticationSession s
        SET s.revokedAt = :now,
            s.revocationReason = :reason
        WHERE s.secretHash = :secretHash 
        AND s.revokedAt is null
        """)
    int revokeSessionBySecretHash(
        @Param("now") Instant now,
        @Param("secretHash") String secretHash,
        @Param("reason") String Reason
    );
}
