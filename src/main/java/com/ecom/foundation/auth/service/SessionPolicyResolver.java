package com.ecom.foundation.auth.service;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.ecom.foundation.auth.config.SessionProperties;
import com.ecom.foundation.auth.config.SessionType;

@Component
public class SessionPolicyResolver {

    private final SessionProperties sessionProperties;

    public SessionPolicyResolver(SessionProperties sessionProperties) {
        this.sessionProperties = sessionProperties;
    }

    public ResolvedSessionPolicy resolve(Collection<? extends GrantedAuthority> authorities) {

        boolean customer = hasAuthority(authorities, "ROLE_CUSTOMER");

        boolean admin = hasAuthority(authorities, "ROLE_ADMIN");

        boolean ops = hasAuthority(authorities, "ROLE_OPS");

        if (customer && !admin && !ops) {
            return new ResolvedSessionPolicy(SessionType.CUSTOMER, sessionProperties.customer());
        }

        if (!customer && (admin || ops)) {
            return new ResolvedSessionPolicy(SessionType.STAFF, sessionProperties.staff());
        }

        throw new IllegalStateException("Unsupported authentication authority combination");
    }

    private boolean hasAuthority(Collection<? extends GrantedAuthority> authorities, String expected) {
        return authorities.stream().anyMatch(authority -> expected.equals(authority.getAuthority()));
    }

    public record ResolvedSessionPolicy(SessionType type, SessionProperties.SessionPolicy policy) {
    }
}