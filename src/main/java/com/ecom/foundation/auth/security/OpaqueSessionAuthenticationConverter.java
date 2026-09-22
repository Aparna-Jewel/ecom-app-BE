package com.ecom.foundation.auth.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import com.ecom.foundation.auth.config.AuthCookieProperties;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class OpaqueSessionAuthenticationConverter implements AuthenticationConverter {

    private final AuthCookieProperties authCookieProperties;

    public OpaqueSessionAuthenticationConverter(AuthCookieProperties authCookieProperties) {
        this.authCookieProperties = authCookieProperties;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        String rawSecret = null;

        for (Cookie cookie : cookies) {

            if (authCookieProperties.name()
                    .equals(cookie.getName())) {

                if (rawSecret != null) {
                    // Ambiguous duplicate session cookies.
                    return null;
                }

                rawSecret = cookie.getValue();
            }
        }

        if (rawSecret == null) {
            return null;
        }

        return OpaqueSessionAuthenticationToken.unauthenticated(rawSecret);
    }
}