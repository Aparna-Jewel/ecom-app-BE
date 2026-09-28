package com.ecom.foundation.auth.dto;

import java.util.List;
import java.util.UUID;

public record CustomerIdentity(UUID publicId, List<String> roles) {
    public CustomerIdentity {
        roles = List.copyOf(roles);
    }
}