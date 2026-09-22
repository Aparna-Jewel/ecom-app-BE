package com.ecom.foundation.auth.security;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ecom.foundation.auth.config.AuthCookieProperties;
import com.ecom.foundation.auth.service.SessionService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class OpaqueSessionAuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final OpaqueSessionAuthenticationConverter authenticationConverter;
    private final SessionService sessionService;
    private final AuthCookieProperties authCookieProperties;
    private final Clock clock;

    public OpaqueSessionAuthenticationFilter(AuthenticationManager authenticationManager, OpaqueSessionAuthenticationConverter authenticationConverter, SessionService sessionService, AuthCookieProperties authCookieProperties, Clock clock) {
        this.authenticationManager = authenticationManager;
        this.authenticationConverter = authenticationConverter;
        this.sessionService = sessionService;
        this.authCookieProperties = authCookieProperties;
        this.clock = clock;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {

            Authentication authenticationRequest = authenticationConverter.convert(request);

            if (authenticationRequest == null) {
                    filterChain.doFilter(request, response);
                    return;
            }

            String rawSecret = (String) authenticationRequest.getCredentials();

            Authentication authenticated = authenticationManager.authenticate(authenticationRequest);

            SessionPrincipal principal = (SessionPrincipal) authenticated.getPrincipal();

            if (shouldRefreshActivity(request)) {

                Optional<String> rotatedSecret = sessionService.refreshActivity(principal.sessionId(), rawSecret, principal.roles());

                if (rotatedSecret.isPresent()) {
                    Duration remainingLifetime = Duration.between(clock.instant(), principal.absoluteExpiresAt());

                    if (remainingLifetime.isNegative()) {
                        remainingLifetime = Duration.ZERO;
                    }

                    ResponseCookie sessionCookie = ResponseCookie
                                    .from(authCookieProperties.name(), rotatedSecret.get())
                                    .httpOnly(true)
                                    .secure(authCookieProperties.secure())
                                    .sameSite(authCookieProperties.sameSite())
                                    .path("/")
                                    .maxAge(remainingLifetime)
                                    .build();

                    response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());
                }
            }

            SecurityContext context = SecurityContextHolder.createEmptyContext();

            context.setAuthentication(authenticated);

            SecurityContextHolder.setContext(context);

        } catch (AuthenticationException exception) {
            SecurityContextHolder.clearContext();
        } catch (DataAccessException exception) {

            SecurityContextHolder.clearContext();

            response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);

            return;
        }

        filterChain.doFilter(request,response);
    }

    private boolean shouldRefreshActivity(HttpServletRequest request) {

        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return false;
        }

        String path = request.getServletPath();

        return !path.equals("/auth/session")
                && !path.equals("/api/security/csrf")
                && !path.equals("/auth/logout")
                && !path.startsWith("/actuator/");
    }
}