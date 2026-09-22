package com.ecom.foundation.auth.service;

import java.time.Clock;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ecom.foundation.auth.entity.Account;
import com.ecom.foundation.auth.entity.AccountStatus;
import com.ecom.foundation.auth.repository.AccountRepository;
import com.ecom.foundation.auth.repository.AccountRoleRepository;

@Service
public class StaffUserDetailsService implements UserDetailsService {

    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_OPS = "OPS";

    private final AccountRepository accountRepository;
    private final AccountRoleRepository accountRoleRepository;
    private final Clock clock;

    public StaffUserDetailsService(AccountRepository accountRepository, AccountRoleRepository accountRoleRepository, Clock clock) {
        this.accountRepository = accountRepository;
        this.accountRoleRepository = accountRoleRepository;
        this.clock = clock;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = accountRepository.findByEmailIgnoreCase(username).orElseThrow(() ->new UsernameNotFoundException("Staff account not found"));

        List<String> roles = accountRoleRepository.findRoleCodesByAccountId(account.getId());

        boolean isStaff = roles.stream().anyMatch(role -> ROLE_ADMIN.equals(role) || ROLE_OPS.equals(role));

        if (!isStaff) {
            throw new UsernameNotFoundException("Staff account not found");
        }

        if (account.getPasswordHash() == null) {
            throw new UsernameNotFoundException("Staff account not found");
        }

        List<SimpleGrantedAuthority> authorities = roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();

        boolean accountLocked = account.getStatus() == AccountStatus.LOCKED || (account.getLockedUntil() != null && account.getLockedUntil().isAfter(clock.instant()));

        boolean enabled = account.getStatus() == AccountStatus.ACTIVE;

        return User
                .withUsername(account.getEmail())
                .password(account.getPasswordHash())
                .authorities(authorities)
                .accountLocked(accountLocked)
                .disabled(!enabled)
                .build();
    }
}