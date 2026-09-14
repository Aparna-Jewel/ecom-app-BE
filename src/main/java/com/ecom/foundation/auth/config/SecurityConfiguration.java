package com.ecom.foundation.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

import com.ecom.foundation.auth.security.OpaqueSessionAuthenticationFilter;
import com.ecom.foundation.auth.service.SessionService;

@Configuration
public class SecurityConfiguration {

    @Bean
    public CookieCsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();

        repository.setCookieName("XSRF-TOKEN");
        repository.setHeaderName("X-XSRF-TOKEN");
        repository.setCookiePath("/");

        repository.setCookieCustomizer(cookie -> cookie.httpOnly(true).sameSite("Lax"));

        return repository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CookieCsrfTokenRepository csrfTokenRepository, SessionService sessionService) throws Exception {

        http
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)

                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository).csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()))

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/security/csrf"
                        ).permitAll()

                        .requestMatchers(
                                HttpMethod.POST,
                                "/auth/otp/send",
                                "/auth/otp/verify",
                                "/auth/customer/complete",
                                "/auth/logout"
                        ).permitAll()

                        .requestMatchers(
                                HttpMethod.GET,
                                "/auth/session",
                                "/auth/account"
                        ).authenticated()

                        .anyRequest().denyAll()
                )

                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((request, response, exception) ->response.setStatus(HttpStatus.FORBIDDEN.value()))
                    );

        http.addFilterBefore(
                new OpaqueSessionAuthenticationFilter(sessionService, "AJ_SESSION"),
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }
}