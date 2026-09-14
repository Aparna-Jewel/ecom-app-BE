package com.ecom.foundation.auth.controller;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecom.foundation.auth.dto.CsrfResponse;

@RestController
@RequestMapping("/api/security")
public class CsrfController {

    @GetMapping("/csrf")
    public ResponseEntity<CsrfResponse> getCsrfToken(CsrfToken csrfToken) {

        CsrfResponse response = new CsrfResponse(
                csrfToken.getToken(),
                csrfToken.getHeaderName()
        );

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(response);
    }
}