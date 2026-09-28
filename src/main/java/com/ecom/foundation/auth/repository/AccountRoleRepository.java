package com.ecom.foundation.auth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.ecom.foundation.auth.entity.AccountRole;
import com.ecom.foundation.auth.entity.AccountRoleId;

public interface AccountRoleRepository extends JpaRepository<AccountRole, AccountRoleId> {
     @Query("""
    select r.code
    from AccountRole ar
    join ar.role r
    where ar.account.id = :accountId
    order by r.code
    """)
    List<String> findRoleCodesByAccountId(@Param ("accountId") Long accountId);
}