package com.ecom.foundation.auth.entity;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;

@Entity
@Getter
@Table(name = "account", schema = "auth")
public class Account{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, unique = true)
    private UUID publicId;

    @Column(name = "email", nullable = true, unique = true, length = 254)
    private String email;

    @Column(name = "mobile", nullable = false, unique = true, length = 16)
    private String mobile;

    @Column(name = "password_hash", length = 255)
    private String passwordHash;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AccountStatus status;

    @Column(name = "failed_login_count", nullable = false)
    private Short failedLoginCount;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "mobile_verified_at")
    private Instant mobileVerifiedAt;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    protected Account() {
        // Default constructor for JPA
    }

    public Account(
        UUID publicId,
        String email, 
        String mobile, 
        String passwordHash, 
        AccountStatus status
    ) {
        this.publicId = publicId;
        this.email = email;
        this.mobile = mobile;
        this.passwordHash = passwordHash;
        this.status = status;
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        this.failedLoginCount = (short) 0;
    }

    public void markMobileVerified(Instant verifiedAt) {
        if (verifiedAt == null) {
            throw new IllegalArgumentException(
                    "Verified time cannot be null"
            );
        }
        this.mobileVerifiedAt = verifiedAt;
        this.updatedAt = verifiedAt;
    }
}