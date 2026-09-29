package com.ecom.foundation.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecom.foundation.auth.dto.AuthenticateRequestModel;
import com.ecom.foundation.auth.dto.EstablishedSession;
import com.ecom.foundation.auth.dto.UserIdentity;
import com.ecom.foundation.auth.otpSetup.dto.OtpChallengeResponse;
import com.ecom.foundation.auth.otpSetup.dto.OtpRequestModel;
import com.ecom.foundation.auth.otpSetup.service.*;
import com.ecom.foundation.auth.service.AuthService;
import com.ecom.foundation.auth.service.SessionAuthenticationService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {


    private final Logger log = LoggerFactory.getLogger(AuthController.class);

    private OtpService otpService;
    private AuthService authService;
    private SessionAuthenticationService sessionAuthenticationService;
    public AuthController(OtpService otpService, AuthService authService, SessionAuthenticationService sessionAuthenticationService) {
        this.otpService = otpService;
        this.authService = authService;
        this.sessionAuthenticationService = sessionAuthenticationService;
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
    public ResponseEntity<EstablishedSession> authenticateCustomer(@Valid @RequestBody AuthenticateRequestModel request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {

        UserIdentity identity = authService.authenticateCustomerRequest(request);

        EstablishedSession establishedSession = sessionAuthenticationService.establishSession(identity, servletRequest, servletResponse);

        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(establishedSession);
    }
}
