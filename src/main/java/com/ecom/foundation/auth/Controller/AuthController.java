package com.ecom.foundation.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecom.foundation.auth.dto.AuthenticateRequestModel;
import com.ecom.foundation.auth.otpSetup.dto.OtpChallengeResponse;
import com.ecom.foundation.auth.otpSetup.dto.OtpRequestModel;
import com.ecom.foundation.auth.otpSetup.service.*;
import com.ecom.foundation.auth.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@Validated
public class AuthController {


    private final Logger log = LoggerFactory.getLogger(AuthController.class);

    private OtpService otpService;
    private AuthService authService;
    public AuthController(OtpService otpService, AuthService authService) {
        this.otpService = otpService;
        this.authService = authService;
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
    public ResponseEntity<Void> authenticateCustomer(@Valid @RequestBody AuthenticateRequestModel request) {
        authService.authenticateCustomerRequest(request);
        return ResponseEntity.ok().build();
    }
}
