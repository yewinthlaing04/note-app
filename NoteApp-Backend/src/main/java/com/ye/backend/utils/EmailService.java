package com.ye.backend.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender javaMailSender;


    public void sendUserRegistrationEmail( String to , String loginlink ){
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("User Account Registration Successful");
        message.setText(" Here link to login to Note App : " + loginlink);
        javaMailSender.send(message);
    }

    public void sendPasswordResetEmail( String to , String resetUrl ){
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset Request");
        message.setText("Click the link to reset your password : " + resetUrl);
        javaMailSender.send(message);
    }
}
