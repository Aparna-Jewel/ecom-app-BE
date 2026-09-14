package com.ecom.foundation.auth.dto;

public record CsrfResponse(
        String token,
        String headerName
) {
}