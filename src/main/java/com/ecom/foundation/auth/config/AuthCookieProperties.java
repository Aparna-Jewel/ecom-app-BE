package com.ecom.foundation.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

@Validated
@ConfigurationProperties(prefix = "app.security.cookie")
public record AuthCookieProperties(

        @NotBlank
        String name,

        @NotNull
        Boolean secure,

        @NotBlank
        @Pattern(
            regexp = "(?i)^(Lax|Strict|None)$",
            message = "SameSite must be Lax, Strict, or None"
        )
        String sameSite

) {

    @AssertTrue(message = "SameSite=None requires Secure=true")
    public boolean isSameSiteConfigurationValid() {
        if (sameSite == null) {
            return true;
        }

        return !"None".equalsIgnoreCase(sameSite) || Boolean.TRUE.equals(secure);
    }

    @AssertTrue(message = "__Host- cookies require Secure=true")
    public boolean isHostCookieConfigurationValid() {
        if (name == null) {
            return true;
        }

        return !name.startsWith("__Host-") || Boolean.TRUE.equals(secure);
    }
}