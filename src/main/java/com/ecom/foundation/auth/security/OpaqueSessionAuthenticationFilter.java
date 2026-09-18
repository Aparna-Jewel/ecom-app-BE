package com.ecom.foundation.auth.security;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ecom.foundation.auth.service.SessionService;
import com.ecom.foundation.common.error.ApplicationException;
import com.ecom.foundation.common.error.ErrorCode;

public class OpaqueSessionAuthenticationFilter extends OncePerRequestFilter {

    private final SessionService sessionService;
    private final String cookieName;

    public OpaqueSessionAuthenticationFilter(SessionService sessionService, String cookieName) {
        this.sessionService = sessionService;
        this.cookieName = cookieName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String rawSecret = readSessionCookie(request);

        if (rawSecret != null) {
            try {
                SessionPrincipal principal = sessionService.authenticate(rawSecret);

                if (shouldRefreshActivity(request)) {
                    sessionService.refreshActivity(principal.sessionId(), rawSecret, principal.roles());
                }

                var authorities = principal.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();

                var authentication = UsernamePasswordAuthenticationToken.authenticated(principal,null,authorities);

                SecurityContext context = SecurityContextHolder.createEmptyContext();

                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);

            } catch (ApplicationException exception) {
                if (exception.getErrorCode() != ErrorCode.AUTHENTICATION_REQUIRED) {
                    throw exception;
                }

                SecurityContextHolder.clearContext();

            } catch (DataAccessException exception) {
                SecurityContextHolder.clearContext();
                response.setHeader("Cache-Control", "no-store");
                response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String readSessionCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        String rawSecret = null;

        for (Cookie cookie : cookies) {
            if (cookieName.equals(cookie.getName())) {
                if (rawSecret != null) {
                    // Reject ambiguous duplicate session cookies.
                    return null;
                }

                rawSecret = cookie.getValue();
            }
        }

        return rawSecret;
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