package com.ecom.foundation.auth.dto;

import java.time.Instant;
import java.util.UUID;

import com.ecom.foundation.auth.config.SessionType;

public record EstablishedSession(
        UUID accountPublicId,
        SessionType sessionType,
        Instant absoluteExpiresAt
) {
}