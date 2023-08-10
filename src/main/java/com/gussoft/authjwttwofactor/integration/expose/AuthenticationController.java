package com.gussoft.authjwttwofactor.integration.expose;

import com.gussoft.authjwttwofactor.core.business.AuthenticationService;
import com.gussoft.authjwttwofactor.integration.transfer.request.AuthenticationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.RegisterRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.VerificationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.response.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v3/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthenticationResponse response = null;
        try {
            response = service.register(request);
            if (request.isMfaEnabled()) {
                return ResponseEntity.ok(response);
            }
        } catch (ConstraintViolationException e) {
            response = new AuthenticationResponse();
            response.setAccessToken(e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @Valid @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        service.refreshToken(request, response);
    }

    @PostMapping("/verify")
    public ResponseEntity<AuthenticationResponse> verifyCode(
            @Valid @RequestBody VerificationRequest verificationRequest) {
        return ResponseEntity.ok(service.verifyCode(verificationRequest));
    }

}
