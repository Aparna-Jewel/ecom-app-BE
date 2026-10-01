package com.ecom.foundation.auth.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Service;

import com.ecom.foundation.auth.config.SessionProperties;
import com.ecom.foundation.auth.dto.CsrfResponse;
import com.ecom.foundation.auth.dto.EstablishedSession;
import com.ecom.foundation.auth.dto.UserIdentity;
import com.ecom.foundation.auth.service.SessionPolicyResolver.ResolvedSessionPolicy;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Service
public class SessionAuthenticationService {

    public static final String SESSION_TYPE = "AJ_SESSION_TYPE";

    public static final String ACCOUNT_PUBLIC_ID ="AJ_ACCOUNT_PUBLIC_ID";

    public static final String ABSOLUTE_EXPIRES_AT ="AJ_ABSOLUTE_EXPIRES_AT";

    public static final String ID_REFRESHED_AT ="AJ_ID_REFRESHED_AT";

    private final SecurityContextRepository securityContextRepository;
    private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

    private final Clock clock;

    private final SessionPolicyResolver sessionPolicyResolver;

    public SessionAuthenticationService(SecurityContextRepository securityContextRepository, SessionAuthenticationStrategy sessionAuthenticationStrategy, SessionPolicyResolver sessiSessionPolicyResolver ,Clock clock) {
        this.securityContextRepository = securityContextRepository;
        this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
        this.sessionPolicyResolver = sessiSessionPolicyResolver;
        this.clock = clock;
    }

    public EstablishedSession establishSession(UserIdentity identity, HttpServletRequest request, HttpServletResponse response) {

        List<SimpleGrantedAuthority> authorities = identity.roles().stream().map(role ->new SimpleGrantedAuthority("ROLE_" + role)).toList();

        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(identity.publicId(), null, authorities);

        ResolvedSessionPolicy resolved = sessionPolicyResolver.resolve(authorities);

        SessionProperties.SessionPolicy policy = resolved.policy();

        sessionAuthenticationStrategy.onAuthentication(authentication, request, response);

        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        if (csrfToken == null) {
            throw new IllegalStateException("CSRF token was not available after authentication");
        }

        CsrfResponse csrfResponse = new CsrfResponse(csrfToken.getToken(), csrfToken.getHeaderName());

        HttpSession session = request.getSession(true);

        Instant now = clock.instant();

        session.setMaxInactiveInterval(Math.toIntExact(policy.idleTimeout().toSeconds()));

        Instant absoluteExpiresAt = now.plus(policy.absoluteTimeout());

        session.setAttribute(SESSION_TYPE, resolved.type().name());

        session.setAttribute( ACCOUNT_PUBLIC_ID, identity.publicId());

        session.setAttribute(ABSOLUTE_EXPIRES_AT, absoluteExpiresAt);

        session.setAttribute(ID_REFRESHED_AT, now);

        SecurityContext context = SecurityContextHolder.createEmptyContext();

        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext( context, request, response);

        return new EstablishedSession(identity.publicId(), resolved.type(), absoluteExpiresAt, csrfResponse);
    }
}