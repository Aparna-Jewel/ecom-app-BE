package com.ecom.foundation.auth.security;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.ecom.foundation.auth.service.SessionService;
import com.ecom.foundation.common.error.ApplicationException;
import com.ecom.foundation.common.error.ErrorCode;

@Component
public class OpaqueSessionAuthenticationProvider implements AuthenticationProvider {

    private final SessionService sessionService;

    public OpaqueSessionAuthenticationProvider(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {

        OpaqueSessionAuthenticationToken token = (OpaqueSessionAuthenticationToken) authentication;

        String rawSecret = (String) token.getCredentials();

        try {
            SessionPrincipal principal = sessionService.authenticate(rawSecret);

            List<GrantedAuthority> authorities = principal.roles().stream()
                            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                            .map(GrantedAuthority.class::cast)
                            .toList();

            return OpaqueSessionAuthenticationToken.authenticated(principal, authorities);

        } catch (ApplicationException exception) {

            if (exception.getErrorCode() == ErrorCode.AUTHENTICATION_REQUIRED) {
                throw new BadCredentialsException("Invalid session", exception);
            }

            throw exception;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OpaqueSessionAuthenticationToken.class.isAssignableFrom(authentication);
    }
}