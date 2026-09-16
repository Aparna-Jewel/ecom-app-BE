package com.ecom.foundation.auth.entity;

import java.time.Instant;
import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;

@Entity 
@Getter 
@Table(name = "authentication_session", schema = "auth")
public class AuthenticationSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_id", nullable = false, updatable = false)
    private Long accountId;

    @Column (name = "secret_hash", nullable = false, length = 64, updatable = false)
    private String secretHash;

    @Column (name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column (name = "last_activity_at", nullable = false)
    private Instant lastActivityAt;

    @Column(name = "idle_expires_at", nullable = false)
    private Instant idleExpiresAt;

    @Column(name = "absolute_expires_at", nullable = false)
    private Instant absoluteExpiresAt;

    @Column(name = "revoked_at", nullable = true)
    private Instant revokedAt;

    @Column(name = "revocation_reason", nullable = true, length = 100)
    private String revocationReason;

    protected AuthenticationSession() {
        // Required by JPA
    }

    public AuthenticationSession(
            Long accountId,
            String secretHash,
            Instant createdAt,
            Instant idleExpiresAt,
            Instant absoluteExpiresAt) {

        this.accountId = Objects.requireNonNull(accountId, "Account ID is required");
        this.secretHash = Objects.requireNonNull(secretHash, "Session secret hash is required");
        this.createdAt = Objects.requireNonNull(createdAt, "Created time is required");
        this.idleExpiresAt = Objects.requireNonNull(idleExpiresAt, "Idle expiry is required");
        this.absoluteExpiresAt = Objects.requireNonNull(absoluteExpiresAt, "Absolute expiry is required");

        this.lastActivityAt = createdAt;
    }
}
