package com.ye.backend.service.impl;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.ye.backend.dtos.UserDTO;
import com.ye.backend.models.AppRole;
import com.ye.backend.models.PasswordResetToken;
import com.ye.backend.models.User;
import com.ye.backend.models.Role;
import com.ye.backend.repository.PasswordResetRepository;
import com.ye.backend.repository.RoleRepository;
import com.ye.backend.repository.UserRepository;
import com.ye.backend.service.IUserService;
import com.ye.backend.utils.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService implements IUserService {

    @Value("${frontend.url}")
    private String frontendUrl;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordResetRepository passwordResetRepository;

    @Autowired
    EmailService emailService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TotpService totpService;


    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        AppRole appRole = AppRole.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole).orElseThrow(
                () -> new RuntimeException("Role not found"));
        user.setRole(role);
        userRepository.save(user);
    }

    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    public UserDTO getUserById(Long id) {
//        return userRepository.findById(id).orElseThrow();
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }
    // *
    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );

        user.setAccountNonLocked(lock);
        userRepository.save(user);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }

    //**
    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    //**
    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );

        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    //**
    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );

        user.setEnabled(enabled);
        userRepository.save(user);
    }

    //**
    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found")
        );

        user.setCredentialsNonExpired(!expire);
        userRepository.save(user);
    }

    //**
    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    @Override
    public void generatePasswordResetToken(String email) {

        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new RuntimeException( "User not found with email :" + email )
        );

        // if found user , create reset token for user
        String token = UUID.randomUUID().toString();

        Instant expiryDate = Instant.now().plus( 1 , ChronoUnit.HOURS);

        PasswordResetToken resetToken = new PasswordResetToken( token , expiryDate ,  user );

        passwordResetRepository.save(resetToken);

        String resetUrl = frontendUrl + "/reset-password?token=" + token;

        // send email to user
        emailService.sendPasswordResetEmail( email , resetUrl );

        }

    @Override
    public void resetPassword(String token, String newPassword) {

    // find token , is not found throw exception
    PasswordResetToken resetToken = passwordResetRepository.findByToken(token).orElseThrow(
            () -> new RuntimeException( "Invalid password reset token")
    );

    // check 2 conditions token expired or isused
    if ( resetToken.isUsed() ){
        throw new RuntimeException("Password reset token has already benn used ");
    }

    if ( resetToken.getExpiryDate().isBefore(Instant.now())){
        throw new RuntimeException("Password reset token is expired ");
    }

    // find user from token entity
    User user = resetToken.getUser();
    // set password
    user.setPassword(passwordEncoder.encode(newPassword));
    // save with repo
    userRepository.save(user);

    // true to isUsed
    resetToken.setUsed(true);

    passwordResetRepository.save(resetToken);


    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User registerUser(User user) {

        if ( user.getPassword() != null ){
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return userRepository.save(user);
    }


    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        try {
            GoogleAuthenticatorKey key = totpService.generateSecret();
            if (key == null) {
                throw new IllegalStateException("Failed to generate 2FA secret");
            }

            user.setTwoFactorSecret(key.getKey());
            userRepository.save(user);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Error generating 2FA secret for user: " + userId, e);
        }
    }

    @Override
    public boolean validate2FACode(Long userId, int code){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return totpService.verifyCode(user.getTwoFactorSecret(), code);
    }

    @Override
    public void enable2FA(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Override
    public void disable2FA(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }
}


