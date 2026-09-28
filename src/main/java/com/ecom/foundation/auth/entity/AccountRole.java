package com.ecom.foundation.auth.entity;

import java.time.Instant;
import java.util.Objects;


import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;

@Entity
@Table(name = "account_role", schema = "auth")
public class AccountRole {
    @EmbeddedId
    private AccountRoleId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("accountId")
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("roleId")
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @Column(name = "assigned_at", nullable = false)
    private Instant assignedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_by_account_id", nullable = true)
    private Account assignedBy;

    protected AccountRole() {
        // Default constructor for JPA
    }

    public AccountRole( Account account, Role role, Account assignedByAccountId) {
        this.account = Objects.requireNonNull(account, "Account cannot be null");
        this.role = Objects.requireNonNull(role, "Role cannot be null");
        this.assignedAt = Instant.now();
        this.assignedBy = assignedByAccountId;
        Long accountId = Objects.requireNonNull(account.getId(),
                "Account must be persisted before assigning a role"
        );

        Short roleId = Objects.requireNonNull(role.getId(),
                "Role must have an ID before it can be assigned"
        );
        this.id = new AccountRoleId(accountId, roleId);
    }

}