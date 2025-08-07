package com.ecomerce.ptit.controller;

import com.ecomerce.ptit.dto.auth.EmailDetails;
import com.ecomerce.ptit.service.EmailService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/mail")
public class EmailSenderController {
    private final EmailService emailService;
    @PostMapping("/send")
    public ResponseEntity<?> sendMail(@RequestBody EmailDetails details) {
        return emailService.sendSimpleMail(details);

    }
    @PostMapping("/sendM")
    public String sendMailWithAttachment(@RequestBody EmailDetails details) {
        return emailService.sendMailWithAttachment(details);
    }
}
