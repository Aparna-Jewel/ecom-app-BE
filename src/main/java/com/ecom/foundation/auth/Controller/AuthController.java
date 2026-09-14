package com.ecom.foundation.auth.controller;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecom.foundation.auth.config.SessionProperties;
import com.ecom.foundation.auth.dto.AccountResponse;
import com.ecom.foundation.auth.dto.AuthenticateRequestModel;
import com.ecom.foundation.auth.dto.CreatedSession;
import com.ecom.foundation.auth.entity.Account;
import com.ecom.foundation.auth.entity.AuthenticationSession;
import com.ecom.foundation.auth.otpSetup.dto.OtpChallengeResponse;
import com.ecom.foundation.auth.otpSetup.dto.OtpRequestModel;
import com.ecom.foundation.auth.otpSetup.service.*;
import com.ecom.foundation.auth.service.AuthService;
import com.ecom.foundation.auth.service.SessionService;
import com.ecom.foundation.common.error.ApplicationException;
import com.ecom.foundation.common.error.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.ecom.foundation.auth.security.SessionPrincipal;

@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {


    private final Logger log = LoggerFactory.getLogger(AuthController.class);

    private OtpService otpService;
    private AuthService authService;
    private SessionProperties sessionProperties;
    private SessionService sessionService;

    public AuthController(OtpService otpService, AuthService authService, SessionProperties sessionProperties, SessionService sessionService) {
        this.otpService = otpService;
        this.authService = authService;
        this.sessionProperties = sessionProperties;
        this.sessionService = sessionService;
    }

    @PostMapping("otp/send")
    public ResponseEntity<OtpChallengeResponse> send(
        @Valid @RequestBody OtpRequestModel request,
        HttpServletRequest servletRequest) {
            // add corealtionId/sessionId for tracing
            log.info("Started processing otp request, {}, {}", "id", request.toString());

            OtpChallengeResponse response =
                    otpService.sendOtp(request);

            return ResponseEntity.accepted().body(response);
    }

    @PostMapping("otp/verify")
    public ResponseEntity<String> verify( @Valid @RequestBody OtpRequestModel request, HttpServletRequest servletRequest) {
        log.info("Started processing request for request {}", request.toString());
        String response = otpService.verifyOtp(request);
        return ResponseEntity.accepted().body(response);
    }

    @PostMapping("/customer/authenticate")
    public ResponseEntity<Void> completeCustomerAuthentication(@Valid @RequestBody AuthenticateRequestModel request) {

        CreatedSession createdSession = authService.completeCustomerSignup(request);

        ResponseCookie sessionCookie = ResponseCookie
                .from("AJ_SESSION", createdSession.rawSecret())
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/")
                .maxAge(sessionProperties.absoluteTimeout())
                .build();

        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, sessionCookie.toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .build();
    }

    @GetMapping("/session")
    public ResponseEntity<Void> getSession() {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).build();
    }

    @GetMapping("/account")
    public ResponseEntity<AccountResponse> getAccount(@AuthenticationPrincipal SessionPrincipal principal) {

        Account account = authService.getAccountById(principal.accountId()).orElseThrow(() -> new ApplicationException(ErrorCode.AUTHENTICATION_REQUIRED));

        AccountResponse response = new AccountResponse(
                account.getPublicId(),
                account.getEmail(),
                account.getMobile(),
                principal.roles()
        );

        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(response);
    }
}
