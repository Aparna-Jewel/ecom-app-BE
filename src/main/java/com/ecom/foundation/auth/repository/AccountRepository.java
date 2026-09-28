package com.ecom.foundation.auth.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.ecom.foundation.auth.entity.Account;


public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByPublicId(UUID publicId);
    Optional<Account> findByEmailIgnoreCase(String email);
    Optional<Account> findByMobile(String mobile);
    boolean existsByEmail(String email);
    boolean existsByMobile(String mobile);

    @Query("""
    select r.code
    from AccountRole ar
    join ar.role r
    where ar.account.id = :accountId
    order by r.code
    """)
    List<String> findRoleCodesByAccountId(@Param("accountId") Long accountId);
}