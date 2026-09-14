package com.ecom.foundation.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ecom.foundation.auth.dto.AuthenticateRequestModel;
import com.ecom.foundation.auth.dto.CreatedSession;
import com.ecom.foundation.auth.entity.Account;
import com.ecom.foundation.auth.entity.AccountRole;
import com.ecom.foundation.auth.entity.AccountStatus;
import com.ecom.foundation.auth.entity.Role;
import com.ecom.foundation.auth.jwt.service.JwtService;
import com.ecom.foundation.auth.otpSetup.config.OtpContext;
import com.ecom.foundation.auth.repository.AccountRepository;
import com.ecom.foundation.auth.repository.AccountRoleRepository;
import com.ecom.foundation.auth.repository.RoleRepository;
import com.ecom.foundation.common.error.ApplicationException;
import com.ecom.foundation.common.error.ErrorCode;
import com.ecom.foundation.terms.Entity.TermStatus;
import com.ecom.foundation.terms.Entity.Terms;
import com.ecom.foundation.terms.Entity.TermsAcceptance;
import com.ecom.foundation.terms.Repository.TermsAcceptanceRepository;
import com.ecom.foundation.terms.Repository.TermsRepository;


@Service
public class AuthService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired 
    private RoleRepository roleRepository;

    @Autowired 
    private AccountRoleRepository accountRoleRepository;

    @Autowired 
    private JwtService jwtService;

    @Autowired 
    private TermsRepository termsRepository;

    @Autowired 
    private TermsAcceptanceRepository termsAcceptanceRepository;

    @Autowired 
    private SessionService sessionService;

    @Transactional(readOnly =true)
    public Optional<Account> getAccountByMobile(String mobile) {
        return accountRepository.findByMobile(mobile);
    }

    public Optional<Account> getAccountById(Long id) {
        return accountRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<String> getAccountRole(Long accountId) {
        return accountRoleRepository.findRoleCodesByAccountId(accountId);
    }

    @Transactional 
    public CreatedSession completeCustomerSignup(AuthenticateRequestModel request) {
        String isdMobileNumber = request.isd() + request.mobile();
        Optional<Account> existingAccount = accountRepository.findByMobile(isdMobileNumber);

        jwtService.validateAndConsumeJwt(request.token(), request.isd(), request.mobile(), OtpContext.CUSTOMER_AUTH);
        
        if (existingAccount.isPresent()) {
            Account accountEntry = existingAccount.get();
            validateCustomerLoginEligibility(accountEntry);
            CreatedSession createdSession = sessionService.createSession(accountEntry.getId());
            return createdSession;
        }

        if (request.email() == null || request.email().isBlank() || request.name() == null || request.name().isBlank()
            || request.lastName() == null || request.lastName().isBlank() || request.termId() == null) {
        
            throw new ApplicationException(ErrorCode.VALIDATION_FAILED, "Customer signup details are required");
        }
        
        if (accountRepository.existsByEmail(request.email())) {
            throw new ApplicationException(ErrorCode.RESOURCE_CONFLICT, "An account already exists for this email address");
        }

        Instant now = Instant.now();

        Account account = new Account(UUID.randomUUID(), request.email(), isdMobileNumber, null, AccountStatus.ACTIVE);
        account.markMobileVerified(now);

        Terms terms = termsRepository.findByStatus(TermStatus.PUBLISHED).orElseThrow(() -> new IllegalStateException("No published terms are available"));

        if (!terms.getId().equals(request.termId())) {
            throw new ApplicationException(ErrorCode.RESOURCE_CONFLICT, "Terms and conditions have changed. Please review and accept the latest version.");
        }

        Account savedAccount = accountRepository.save(account);

        Role customerRole = roleRepository.findByCode("CUSTOMER");

        accountRoleRepository.save(new AccountRole(savedAccount, customerRole, null));


        termsAcceptanceRepository.save(new TermsAcceptance(savedAccount.getId(), terms));
        
        return sessionService.createSession(savedAccount.getId());
    }

    private void validateCustomerLoginEligibility(Account account) {

    Instant now = Instant.now();

    if (account.getStatus() != AccountStatus.ACTIVE
            || (account.getLockedUntil() != null
                && now.isBefore(account.getLockedUntil()))) {
        throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
    }

    List<String> roles =
            accountRoleRepository.findRoleCodesByAccountId(account.getId());

    if (!roles.contains("CUSTOMER")
            || roles.contains("ADMIN")
            || roles.contains("OPS")) {
        throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
    }
}
}