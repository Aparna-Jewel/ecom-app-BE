package com.ecom.foundation.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.hibernate.annotations.ListIndexJavaType;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.ecom.foundation.auth.config.SessionProperties;
import com.ecom.foundation.auth.dto.CreatedSession;
import com.ecom.foundation.auth.entity.Account;
import com.ecom.foundation.auth.entity.AccountRole;
import com.ecom.foundation.auth.entity.AccountStatus;
import com.ecom.foundation.auth.entity.AuthenticationSession;
import com.ecom.foundation.auth.repository.AccountRepository;
import com.ecom.foundation.auth.repository.AccountRoleRepository;
import com.ecom.foundation.auth.repository.SessionRepository;
import com.ecom.foundation.auth.security.SessionPrincipal;
import com.ecom.foundation.common.error.ApplicationException;
import com.ecom.foundation.common.error.ErrorCode;
import com.ecom.foundation.common.helper.RandomGenerator;

@Service
public class SessionService {

    private static final int SESSION_SECRET_BYTE_LENGTH = 32;

    private final RandomGenerator randomGenerator;
    private final SessionRepository sessionRepository;
    private final SessionProperties sessionProperties;
    private final Clock clock;
    private final AccountRepository accountRepository;
    private final AccountRoleRepository accountRoleRepository;

    public SessionService(RandomGenerator randomGenerator, 
        SessionRepository sessionRepository, 
        SessionProperties sessionProperties, 
        Clock clock, 
        AccountRepository accountRepository,
        AccountRoleRepository accountRoleRepository) {

        this.randomGenerator = randomGenerator;
        this.sessionRepository = sessionRepository;
        this.sessionProperties = sessionProperties;
        this.clock = clock;
        this.accountRepository = accountRepository; 
        this.accountRoleRepository = accountRoleRepository;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public CreatedSession createSession(Long accountId) {
        Objects.requireNonNull(accountId, "Account ID is required");

        String rawSecret = generateSecret();
        String secretHash = hashSecret(rawSecret);

        Instant now = clock.instant();

        AuthenticationSession session = new AuthenticationSession(accountId, secretHash, now, now.plus(sessionProperties.idleTimeout()), now.plus(sessionProperties.absoluteTimeout()));

        AuthenticationSession savedSession = sessionRepository.save(session);

        return new CreatedSession(rawSecret, savedSession);
    }
    
    @Transactional(readOnly = true)
    public SessionPrincipal authenticate(String rawSecret) {
        if (rawSecret == null || !rawSecret.matches("^[A-Za-z0-9_-]{43}$")) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        String secretHash = hashSecret(rawSecret);

        AuthenticationSession fetchedSessionData = sessionRepository.findBySecretHash(secretHash).orElseThrow(() -> new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED));

        Instant now = clock.instant();

        if (fetchedSessionData.getRevokedAt() != null || !now.isBefore(fetchedSessionData.getIdleExpiresAt()) || !now.isBefore(fetchedSessionData.getAbsoluteExpiresAt())) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        Account account = accountRepository.findById(fetchedSessionData.getAccountId()).orElseThrow(() -> new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED));

        if(account.getStatus() != AccountStatus.ACTIVE || (account.getLockedUntil() != null && now.isBefore(account.getLockedUntil()))) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }

        List<String> roles = accountRoleRepository.findRoleCodesByAccountId(account.getId()); 

        return new SessionPrincipal(
            fetchedSessionData.getId(),
            account.getId(),
            account.getPublicId(),
            roles
            );
    }

    @Transactional 
    public void revokeSession(String rawSecret, String reason) {
        String secretHash = hashSecret(rawSecret);
        Optional<AuthenticationSession> session = sessionRepository.findBySecretHash(secretHash);
        if(!session.isPresent()) {
            throw new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED);
        }
        int revokedSession = sessionRepository.revokeSessionBySecretHash(Instant.now(), secretHash, reason);
        if(revokedSession == 0) {
            throw new ApplicationException(ErrorCode.INTERNAL_ERROR);
        } 
    }
    private String generateSecret() {
        byte[] randomBytes = randomGenerator.secureRandomBytes(SESSION_SECRET_BYTE_LENGTH);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String hashSecret(String rawSecret) {
        if (rawSecret == null || rawSecret.isBlank()) {
            throw new IllegalArgumentException("Session secret must not be blank");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(rawSecret.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable",exception);
        }
    }
}