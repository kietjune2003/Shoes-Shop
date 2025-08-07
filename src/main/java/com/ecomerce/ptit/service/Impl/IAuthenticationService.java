package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.dto.ApiResponse;
import com.ecomerce.ptit.dto.auth.*;
import com.ecomerce.ptit.exception.ErrorResponse;
import com.ecomerce.ptit.model.*;
import com.ecomerce.ptit.repository.*;
import com.ecomerce.ptit.service.*;
import com.ecomerce.ptit.security.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Date;
import java.util.HashSet;
import java.util.Random;

import static com.ecomerce.ptit.constants.ErrorMessage.*;

@Service
@RequiredArgsConstructor
@Slf4j // 🔧 Cho phép ghi log
public class IAuthenticationService implements AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final CartRepository cartRepository;

    // ✅ Đăng ký tài khoản mới và gửi OTP xác thực
    @Override
    public ResponseEntity<?> register(RegisterRequest request) {
        log.info("Bắt đầu xử lý đăng ký tài khoản cho email: {}", request.getEmail());

        try {
            var existedUser = userRepository.findByEmail(request.getEmail());
            if (existedUser.isPresent()) {
                log.warn("Email đã tồn tại: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.CONFLICT).body(EMAIL_IN_USE);
            }

            var role = new HashSet<Role>();
            role.add(roleRepository.findRoleByRole(EnumRole.ROLE_USER.name()));

            var user = new User();
            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setEmail(request.getEmail());
            user.setRoles(role);
            user.setActive(true);
            user.setPassword(passwordEncoder.encode(request.getPassword()));

            Cart cart = new Cart();
            cart.setUser(user);

            // Gửi mã OTP
            var otp = generateOTP(user);
            EmailDetails emailDetails = new EmailDetails();
            emailDetails.setSubject("Xác thực tài khoản mới!");
            emailDetails.setRecipient(user.getEmail());
            emailDetails.setMsgBody("Chào " + request.getEmail() +
                    ",\nChúng tôi rất vui thông báo tài khoản bạn đã được tạo...\nMã OTP: " + otp);
            emailService.sendSimpleMail(emailDetails);

            // Lưu thông tin
            userRepository.save(user);
            cartRepository.save(cart);

            log.info("Đăng ký thành công, đã gửi OTP đến email: {}", user.getEmail());
            return ResponseEntity.ok(ApiResponse.builder()
                    .statusCode(200)
                    .message("OTP has been sent to your email. Please check your email!")
                    .description("Successfully")
                    .timestamp(new Date())
                    .build());
        } catch (Exception exception) {
            log.error("Lỗi trong quá trình đăng ký: {}", exception.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.builder()
                    .statusCode(403)
                    .message(String.valueOf(HttpStatus.FORBIDDEN))
                    .description(exception.getLocalizedMessage())
                    .timestamp(new Date())
                    .build());
        }
    }

    // ✅ Cập nhật mật khẩu
    @Override
    public ResponseEntity<?> updatePassword(UpdatePasswordRequest updatePasswordRequest, Principal connectedUser) {
        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();
        log.info("Yêu cầu đổi mật khẩu của user: {}", user.getEmail());

        // Kiểm tra mật khẩu cũ
        if (!passwordEncoder.matches(updatePasswordRequest.getPassword(), user.getPassword())) {
            log.warn("Mật khẩu hiện tại không đúng cho user: {}", user.getEmail());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.builder()
                    .statusCode(400)
                    .message("FORBIDDEN")
                    .description(INCORRECT_PASSWORD)
                    .timestamp(new Date())
                    .build());
        }

        // Kiểm tra trùng mật khẩu cũ
        if (updatePasswordRequest.getNewPassword().equals(updatePasswordRequest.getPassword())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.builder()
                    .statusCode(400)
                    .message("FORBIDDEN")
                    .description(NEW_PASSWORD_IS_SAME_CURRENT_PASSWORD)
                    .timestamp(new Date())
                    .build());
        }

        // Cập nhật
        user.setPassword(passwordEncoder.encode(updatePasswordRequest.getNewPassword()));
        userRepository.save(user);
        log.info("Mật khẩu đã được cập nhật cho user: {}", user.getEmail());
        return ResponseEntity.ok(ApiResponse.builder()
                .statusCode(200)
                .message("OK")
                .description("Password changed successfully!")
                .timestamp(new Date())
                .build());
    }

    // ✅ Xác thực OTP khi đăng nhập lần đầu
    @Override
    public ResponseEntity<?> validateLoginOTP(OtpRequest request) {
        var user = userRepository.findByEmail(request.getEmail());
        log.info("Xác thực OTP cho email: {}", request.getEmail());

        if (user.isPresent()) {
            if (user.get().isEmailActive()) {
                log.warn("Email đã được active trước đó: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ErrorResponse.builder()
                        .statusCode(400)
                        .message("BAD_REQUEST")
                        .description("Invalid request!")
                        .timestamp(new Date())
                        .build());
            }

            if (passwordEncoder.matches(request.getOneTimePassword(), user.get().getOneTimePassword())) {
                clearOTP(user.get());
                log.info("OTP hợp lệ, kích hoạt email: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.builder()
                        .statusCode(201)
                        .message("CREATED")
                        .description("Email has been activated successfully! Please login!")
                        .timestamp(new Date())
                        .build());
            } else {
                log.warn("OTP không hợp lệ cho email: {}", request.getEmail());
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.builder()
                        .statusCode(403)
                        .message("FORBIDDEN")
                        .description(OTP_NOT_VALID)
                        .timestamp(new Date())
                        .build());
            }
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ErrorResponse.builder()
                    .statusCode(404)
                    .message("NOT_FOUND")
                    .description(EMAIL_NOT_FOUND)
                    .timestamp(new Date())
                    .build());
        }
    }

    // ✅ Kiểm tra OTP khi đổi mật khẩu
    @Override
    public boolean validateChangePasswordOTP(OtpRequest request) {
        var user = userRepository.findByEmail(request.getEmail());
        if (user.isPresent() && !user.get().getOneTimePassword().isEmpty()) {
            boolean isValid = passwordEncoder.matches(request.getOneTimePassword(), user.get().getOneTimePassword());
            if (isValid) {
                clearOTP(user.get());
                return true;
            }
        }
        return false;
    }

    // ✅ Xác thực đăng nhập, sinh JWT + cookie refreshToken
    @Override
    public ResponseEntity<?> authenticate(AuthenticationRequest request, HttpServletRequest httpServletRequest, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("Đăng nhập: {}", request.getEmail());

        var user = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            log.warn("Thông tin đăng nhập không đúng: {}", request.getEmail());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ErrorResponse.builder()
                    .statusCode(404)
                    .message("NOT_FOUND")
                    .description(INCORRECT_PASSWORD_OR_EMAIL)
                    .timestamp(new Date())
                    .build());
        }

        if (!user.isEmailActive()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.builder()
                    .statusCode(403)
                    .message("FORBIDDEN")
                    .description(INACTIVE_EMAIL)
                    .timestamp(new Date())
                    .build());
        }

        var jwtToken = jwtService.generateToken(user, user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);

        Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        response.addCookie(refreshTokenCookie);

        return ResponseEntity.ok(AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build());
    }

    // ✅ Lưu token mới cho user
    private void saveUserToken(User user, String jwtToken) {
        tokenRepository.save(Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .build());
    }

    // ✅ Revoke tất cả token cũ của user
    public void revokeAllUserTokens(User user) {
        var validTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        validTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validTokens);
    }

    // ✅ Refresh accessToken từ cookie chứa refreshToken
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Cookie[] cookies = request.getCookies();
        String refreshToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null) {
            log.warn("Không tìm thấy cookie refreshToken!");
            new ObjectMapper().writeValue(response.getOutputStream(), ErrorResponse.builder()
                    .statusCode(400)
                    .message("NOT_FOUND")
                    .description("Did not find any cookies!")
                    .timestamp(new Date())
                    .build());
            return;
        }

        String email = jwtService.extractEmail(refreshToken);
        var user = userRepository.findByEmail(email).orElse(null);
        if (user != null && jwtService.isFreshTokenValid(refreshToken, user)) {
            var newAccessToken = jwtService.generateToken(user, user);
            var newRefreshToken = jwtService.generateRefreshToken(user);

            Cookie newCookie = new Cookie("refreshToken", newRefreshToken);
            newCookie.setHttpOnly(true);
            response.addCookie(newCookie);

            revokeAllUserTokens(user);
            saveUserToken(user, newAccessToken);

            new ObjectMapper().writeValue(response.getOutputStream(), AuthenticationResponse.builder()
                    .accessToken(newAccessToken)
                    .build());
        }
    }

    // ✅ Tạo mã OTP và lưu vào user
    public String generateOTP(User user) throws UnsupportedEncodingException, MessagingException {
        String numbers = "0123456789";
        Random rnd = new Random();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            otp.append(numbers.charAt(rnd.nextInt(numbers.length())));
        }

        String plainOTP = otp.toString();
        user.setOneTimePassword(passwordEncoder.encode(plainOTP));
        user.setOtpRequestedTime(new Date());
        return plainOTP;
    }

    // ✅ Xoá OTP sau khi đã xác thực
    public void clearOTP(User user) {
        user.setOneTimePassword(null);
        user.setOtpRequestedTime(null);
        user.setEmailActive(true);
        userRepository.save(user);
    }
}
