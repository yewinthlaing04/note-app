package com.ye.backend.service;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.ye.backend.dtos.UserDTO;
import com.ye.backend.models.Role;
import com.ye.backend.models.User;

import java.util.List;
import java.util.Optional;

public interface IUserService {

    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    void updateAccountLockStatus(Long userId, boolean lock);

    User findByUsername(String username);

    List<Role> getAllRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String password);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String newPassword);

    Optional<User> findByEmail(String email);

    User registerUser(User user);

   // GoogleAuthenticatorKey generate2FASecret(Long userId);

    GoogleAuthenticatorKey generate2FASecret(Long userId);

    boolean validate2FACode(Long userId, int code);

    void enable2FA(Long userId);

    void disable2FA(Long userId);


}
