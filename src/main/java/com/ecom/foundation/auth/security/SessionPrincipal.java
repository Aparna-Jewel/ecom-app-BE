package com.ecom.foundation.auth.security;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record SessionPrincipal(
        Long sessionId,
        Long accountId,
        UUID accountPublicId,
        List<String> roles,
        Instant absoluteExpiresAt
) {
    public SessionPrincipal {
        roles = List.copyOf(roles);
    }
}