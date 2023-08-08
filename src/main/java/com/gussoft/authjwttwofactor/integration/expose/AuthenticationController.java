package com.gussoft.authjwttwofactor.integration.expose;

import com.gussoft.authjwttwofactor.core.business.AuthenticationService;
import com.gussoft.authjwttwofactor.integration.transfer.request.AuthenticationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.RegisterRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.VerificationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.response.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v3/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        AuthenticationResponse response = service.register(request);
        if (request.isMfaEnabled()) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        service.refreshToken(request, response);
    }

    @PostMapping("/verify")
    public ResponseEntity<AuthenticationResponse> verifyCode(
            @RequestBody VerificationRequest verificationRequest) {
        return ResponseEntity.ok(service.verifyCode(verificationRequest));
    }

}
