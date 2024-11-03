package com.ye.backend.controller;


import com.ye.backend.dtos.UserDTO;
import com.ye.backend.models.Role;
import com.ye.backend.models.User;
import com.ye.backend.repository.UserRepository;
import com.ye.backend.service.impl.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ROLE_ADMIN')")
@CrossOrigin(origins = "http://localhost:3000" , maxAge = 3600 , allowCredentials = "true")
public class AdminController {

    @Autowired
    UserService userService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/getusers")
    public ResponseEntity<List<User>> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(),
                HttpStatus.OK);
    }

    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(@RequestParam Long userId,
                                                 @RequestParam String roleName) {
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok("User role updated");
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id) {
        return new ResponseEntity<>(userService.getUserById(id),
                HttpStatus.OK);
    }

    @GetMapping("/roles")
    public List<Role> getAllRoles() {
        return userService.getAllRoles();
    }



    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestParam Long userId,
                                                 @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok("Password updated");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }


    @PutMapping("/update-lock-status")
    public ResponseEntity<String> updateAccountLockStatus(@RequestParam Long userId,
                                                          @RequestParam boolean lock) {
        userService.updateAccountLockStatus(userId, lock);
        return ResponseEntity.ok("Account lock status updated");
    }


    @PutMapping("/update-expiry-status")
    public ResponseEntity<String> updateAccountExpiryStatus(@RequestParam Long userId,
                                                            @RequestParam boolean expire) {
        userService.updateAccountExpiryStatus(userId, expire);
        return ResponseEntity.ok("Account expiry status updated");
    }

    @PutMapping("/update-enabled-status")
    public ResponseEntity<String> updateAccountEnabledStatus(@RequestParam Long userId,
                                                             @RequestParam boolean enabled) {
        userService.updateAccountEnabledStatus(userId, enabled);
        return ResponseEntity.ok("Account enabled status updated");
    }

    @PutMapping("/update-credentials-expiry-status")
    public ResponseEntity<String> updateCredentialsExpiryStatus(@RequestParam Long userId, @RequestParam boolean expire) {
        userService.updateCredentialsExpiryStatus(userId, expire);
        return ResponseEntity.ok("Credentials expiry status updated");
    }


}
