package com.gussoft.authjwttwofactor.core.business;

import com.gussoft.authjwttwofactor.integration.transfer.request.AuthenticationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.RegisterRequest;
import com.gussoft.authjwttwofactor.integration.transfer.request.VerificationRequest;
import com.gussoft.authjwttwofactor.integration.transfer.response.AuthenticationResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface AuthenticationService {

    AuthenticationResponse register(RegisterRequest request);

    AuthenticationResponse authenticate(AuthenticationRequest request);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;

    AuthenticationResponse verifyCode(VerificationRequest verificationRequest);

}
