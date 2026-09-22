package com.ecom.foundation.auth.security;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public final class OpaqueSessionAuthenticationToken extends AbstractAuthenticationToken {

    private final SessionPrincipal principal;
    private final String rawSecret;

    private OpaqueSessionAuthenticationToken(String rawSecret) {
        super(List.of());

        this.rawSecret = Objects.requireNonNull(rawSecret, "Raw session secret is required");

        this.principal = null;

        super.setAuthenticated(false);
    }

    private OpaqueSessionAuthenticationToken(SessionPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);

        this.principal = Objects.requireNonNull(principal, "Session principal is required");

        this.rawSecret = null;

        super.setAuthenticated(true);
    }

    public static OpaqueSessionAuthenticationToken unauthenticated(String rawSecret) {
        return new OpaqueSessionAuthenticationToken(rawSecret);
    }

    public static OpaqueSessionAuthenticationToken authenticated(SessionPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
        return new OpaqueSessionAuthenticationToken(principal, authorities);
    }

    @Override
    public Object getCredentials() {
        return rawSecret;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {

        if (authenticated) {
            throw new IllegalArgumentException("Cannot mark OpaqueSessionAuthenticationToken as authenticated directly");
        }

        super.setAuthenticated(false);
    }
}