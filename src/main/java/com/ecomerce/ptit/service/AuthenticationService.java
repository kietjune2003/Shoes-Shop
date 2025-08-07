package com.ecomerce.ptit.service;

import com.ecomerce.ptit.dto.auth.AuthenticationRequest;
import com.ecomerce.ptit.dto.auth.OtpRequest;
import com.ecomerce.ptit.dto.auth.RegisterRequest;
import com.ecomerce.ptit.dto.auth.UpdatePasswordRequest;
import com.ecomerce.ptit.model.User;
import io.jsonwebtoken.io.IOException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.security.Principal;

public interface AuthenticationService {
    ResponseEntity<?> authenticate(AuthenticationRequest request, HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws java.io.IOException;
    ResponseEntity<?> register(RegisterRequest request);

    ResponseEntity<?> updatePassword(UpdatePasswordRequest updatePasswordRequest, Principal connectedUser);

    ResponseEntity<?> validateLoginOTP(OtpRequest request);

    boolean validateChangePasswordOTP(OtpRequest request);
    void revokeAllUserTokens(User user);
    void refreshToken(HttpServletRequest request,
                             HttpServletResponse response) throws IOException, java.io.IOException;

}
