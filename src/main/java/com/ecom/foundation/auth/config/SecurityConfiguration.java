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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

@Configuration
public class SecurityConfiguration {

    @Bean
    CookieCsrfTokenRepository csrfTokenRepository(AuthCookieProperties cookieProperties) {

        CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();

        repository.setCookieName("XSRF-TOKEN");
        repository.setHeaderName("X-XSRF-TOKEN");
        repository.setCookiePath("/");

        repository.setCookieCustomizer(cookie -> cookie
                .httpOnly(true)
                .secure(cookieProperties.secure())
                .sameSite(cookieProperties.sameSite())
                .path("/")
        );

        return repository;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, CookieCsrfTokenRepository csrfTokenRepository) throws Exception {

        XorCsrfTokenRequestAttributeHandler csrfRequestHandler = new XorCsrfTokenRequestAttributeHandler();

        http
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .requestCache(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .csrf(csrf -> csrf .csrfTokenRepository(csrfTokenRepository) .csrfTokenRequestHandler(csrfRequestHandler))
            .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET,"/api/security/csrf")
                        .permitAll()
                        .requestMatchers(
                                HttpMethod.POST,
                                "/auth/otp/send",
                                "/auth/otp/verify",
                                "/auth/customer/authenticate"
                        )
                        .permitAll()
                        .requestMatchers(
                                HttpMethod.GET,
                                "/actuator/health",
                                "/actuator/info"
                        )
                        .permitAll()

                        /*
                         * We'll add authenticated customer APIs here later.
                         *
                         * Everything not explicitly exposed stays closed.
                         */
                        .anyRequest()
                        .denyAll()
                )

                /*
                 * REST-friendly 401 / 403.
                 *
                 * Later we can replace these with the project's standardized
                 * API error payloads.
                 */
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                new HttpStatusEntryPoint(
                                        HttpStatus.UNAUTHORIZED
                                )
                        )
                        .accessDeniedHandler(
                                (request, response, exception) ->
                                        response.setStatus(
                                                HttpStatus.FORBIDDEN.value()
                                        )
                        )
                );

        return http.build();
    }
}