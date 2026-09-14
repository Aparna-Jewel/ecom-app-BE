package com.ecom.foundation.auth.dto;

import java.util.List;
import java.util.UUID;

public record AccountResponse(
        String fullName,
        UUID publicId,
        String email,
        String mobile,
        List<String> role
) {
}