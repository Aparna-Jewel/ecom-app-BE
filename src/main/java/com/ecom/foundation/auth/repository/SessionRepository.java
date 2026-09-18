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

    @Modifying
    @Query("""
        UPDATE AuthenticationSession s
           SET s.lastActivityAt = :now,
               s.idleExpiresAt =
                   CASE
                       WHEN s.absoluteExpiresAt < :candidateIdleExpiry
                       THEN s.absoluteExpiresAt
                       ELSE :candidateIdleExpiry
                   END,
               s.secretHash = :newSecretHash
         WHERE s.id = :sessionId
           AND s.secretHash = :currentSecretHash
           AND s.revokedAt IS NULL
           AND s.idleExpiresAt > :now
           AND s.absoluteExpiresAt > :now
           AND s.lastActivityAt <= :refreshBefore
    """)
    int refreshActivity(
            @Param("sessionId") Long sessionId,
            @Param("now") Instant now,
            @Param("candidateIdleExpiry") Instant candidateIdleExpiry,
            @Param("refreshBefore") Instant refreshBefore,
            @Param("currentSecretHash") String currentSecretHash,
            @Param("newSecretHash") String newSecretHash
    );
}
