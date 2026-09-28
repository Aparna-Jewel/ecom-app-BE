package com.ecom.foundation.auth.dto;

import java.util.List;
import java.util.UUID;

public record UserIdentity(UUID publicId, List<String> roles) {

    public UserIdentity {
        roles = List.copyOf(roles);
    }
}