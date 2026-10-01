package com.ecom.foundation.auth.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.aop.framework.AopConfigException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ecom.foundation.auth.dto.AuthenticateRequestModel;
import com.ecom.foundation.auth.dto.UserIdentity;
import com.ecom.foundation.auth.entity.Account;
import com.ecom.foundation.auth.entity.AccountRole;
import com.ecom.foundation.auth.entity.AccountStatus;
import com.ecom.foundation.auth.entity.CustomerProfile;
import com.ecom.foundation.auth.entity.Role;
import com.ecom.foundation.auth.jwt.service.JwtService;
import com.ecom.foundation.auth.otpSetup.config.OtpContext;
import com.ecom.foundation.auth.repository.AccountRepository;
import com.ecom.foundation.auth.repository.AccountRoleRepository;
import com.ecom.foundation.auth.repository.CustomerProfileRepository;
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
    private JwtService jwtService;

    @Autowired 
    private TermsRepository termsRepository;

    @Autowired 
    private TermsAcceptanceRepository termsAcceptanceRepository;

    @Autowired 
    private RoleRepository roleRepository;

    @Autowired 
    private AccountRoleRepository accountRoleRepository;

    @Autowired 
    private CustomerProfileRepository customerProfileRepository;

    @Autowired 
    private SessionAuthenticationService sessionAuthenticationService;
    
    private Clock clock;
    public AuthService(Clock clock) {
        this.clock = clock;
    }

    @Transactional 
    public UserIdentity authenticateCustomerRequest(AuthenticateRequestModel request){
        String isdMobileNumber = request.isd() + request.mobile();
        
        jwtService.validateAndConsumeJwt(request.token(), request.isd(), request.mobile(), OtpContext.CUSTOMER_SIGNUP);
        Optional<Account> requestAccount = accountRepository.findByMobile(isdMobileNumber);
        
        if(requestAccount.isPresent()) {
            Account account = requestAccount.get();
            validateCustomerLoginEligibility(account);
            return new UserIdentity(account.getPublicId(), List.of("CUSTOMER"));
        }

        if (request.name() == null || request.name().isBlank() || request.termId() == null) {
            throw new ApplicationException(ErrorCode.VALIDATION_FAILED, "Customer signup details are required");
        }
        
        if (accountRepository.existsByEmail(request.email())) {
            throw new ApplicationException(ErrorCode.RESOURCE_CONFLICT, "An account already exists for this email address");
        }

        String name = request.name() + " " + request.lastName();
        Instant now = clock.instant();
        Account newAccount = new Account(UUID.randomUUID(), request.email(), isdMobileNumber, null, AccountStatus.ACTIVE);
        newAccount.markMobileVerified(now);

        Terms getActiveTerms = termsRepository.findByStatus(TermStatus.PUBLISHED).orElseThrow(() -> new IllegalArgumentException());
        
        if(!getActiveTerms.getId().equals(request.termId())) {
            throw new ApplicationException(ErrorCode.RESOURCE_CONFLICT, " Terms have changed please retry");
        }

        Account savedAccount = accountRepository.save(newAccount);

        Role getRole = roleRepository.findByCode("CUSTOMER").get();
        accountRoleRepository.save(new AccountRole(savedAccount, getRole, null));

        termsAcceptanceRepository.save(new TermsAcceptance(savedAccount.getId(), getActiveTerms));

        customerProfileRepository.save(new CustomerProfile(savedAccount.getId(), name));

        return new UserIdentity(savedAccount.getPublicId(), List.of("CUSTOMER"));
    }

    private void validateCustomerLoginEligibility(Account account) {

        if (account.getStatus() != AccountStatus.ACTIVE) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        Instant now = clock.instant();

        if (account.getLockedUntil() != null && now.isBefore(account.getLockedUntil())) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        List<String> roles = accountRoleRepository.findRoleCodesByAccountId(account.getId());

        if (!roles.contains("CUSTOMER") || roles.contains("ADMIN") || roles.contains("OPS")) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }
    }
}