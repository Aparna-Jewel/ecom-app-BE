package com.ecom.foundation.auth.config;

import java.time.Clock;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

import com.ecom.foundation.auth.security.OpaqueSessionAuthenticationConverter;
import com.ecom.foundation.auth.security.OpaqueSessionAuthenticationFilter;
import com.ecom.foundation.auth.security.OpaqueSessionAuthenticationProvider;
import com.ecom.foundation.auth.service.SessionService;

import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ecom.foundation.auth.service.StaffUserDetailsService;

@Configuration
public class SecurityConfiguration {
        @Bean
        public AuthenticationManager authenticationManager(OpaqueSessionAuthenticationProvider opaqueSessionAuthenticationProvider, DaoAuthenticationProvider staffDaoAuthenticationProvider) {
                return new ProviderManager(opaqueSessionAuthenticationProvider, staffDaoAuthenticationProvider);
        }

        @Bean
        public CookieCsrfTokenRepository csrfTokenRepository(AuthCookieProperties authCookieProperties) {

            CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();

            repository.setCookieName("XSRF-TOKEN");
            repository.setHeaderName("X-XSRF-TOKEN");
            repository.setCookiePath("/");

            repository.setCookieCustomizer(cookie -> cookie
                            .httpOnly(true)
                            .secure(authCookieProperties.secure())
                            .sameSite(authCookieProperties.sameSite())
                            .path("/")
                    );

            return repository;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        }

        @Bean
        public DaoAuthenticationProvider staffDaoAuthenticationProvider(StaffUserDetailsService staffUserDetailsService, PasswordEncoder passwordEncoder) {
            DaoAuthenticationProvider provider = new DaoAuthenticationProvider(staffUserDetailsService);
            provider.setPasswordEncoder(passwordEncoder);

            return provider;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http, CookieCsrfTokenRepository csrfTokenRepository, SessionService sessionService, AuthCookieProperties authCookieProperties, AuthenticationManager authenticationManager,
            OpaqueSessionAuthenticationConverter authenticationConverter, Clock clock) throws Exception {

            OpaqueSessionAuthenticationFilter opaqueSessionFilter = new OpaqueSessionAuthenticationFilter(authenticationManager, authenticationConverter, sessionService, authCookieProperties, clock);

            http
                .sessionManagement(session ->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .requestCache(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository).csrfTokenRequestHandler(new XorCsrfTokenRequestAttributeHandler()))
                .authorizeHttpRequests(authorize -> authorize.requestMatchers(HttpMethod.GET,"/api/security/csrf").permitAll()
                .requestMatchers(
                            HttpMethod.POST,
                            "/auth/otp/send",
                            "/auth/otp/verify",
                            "/auth/customer/authenticate",
                            "/auth/logout"
                )
                .permitAll()
                .requestMatchers(
                        HttpMethod.GET,
                        "/auth/session",
                        "/auth/account"
                )
                .authenticated()                
                .anyRequest()
                .denyAll())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))         
                .accessDeniedHandler((request, response, exception) -> response.setStatus(HttpStatus.FORBIDDEN.value())));

            http.addFilterBefore(opaqueSessionFilter, AnonymousAuthenticationFilter.class);
            return http.build();
        }
}