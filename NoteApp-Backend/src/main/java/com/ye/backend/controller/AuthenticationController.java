package com.ye.backend.controller;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.ye.backend.models.AppRole;
import com.ye.backend.models.Role;
import com.ye.backend.models.User;
import com.ye.backend.repository.RoleRepository;
import com.ye.backend.repository.UserRepository;
import com.ye.backend.security.jwt.JwtUtils;
import com.ye.backend.security.request.LoginRequest;
import com.ye.backend.security.request.SignUpRequest;
import com.ye.backend.security.response.LoginResponse;
import com.ye.backend.security.response.MessageResponse;
import com.ye.backend.security.response.UserInfoResponse;
import com.ye.backend.security.services.UserDetailsImpl;
import com.ye.backend.service.impl.TotpService;
import com.ye.backend.service.impl.UserService;
import com.ye.backend.utils.AuthUtil;
import com.ye.backend.utils.EmailService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:3000" , maxAge = 3600, allowCredentials = "true")
public class AuthenticationController {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleReposiory;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserService userService;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EmailService emailService;

    @Value("${frontend.url}")
    private String frontendUrl;

    @Autowired
    TotpService totpService;

    @Autowired
    private AuthUtil authUtil;


    String loginlink = frontendUrl + "/login";

    // endpoint for user login

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest) {

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername() ,
                            loginRequest.getPassword())
            );
        }catch ( AuthenticationException e ) {
            Map<String , Object > map = new HashMap<>();
            map.put("message" , "Bad credentials ");
            map.put("status" , false );
            return new ResponseEntity<Object>(map , HttpStatus.NOT_FOUND);
        }

        // set authentication in security context holder
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails =( UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername( userDetails);

        // collect roles from userdetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // prepare the response body , now including the jwt token directly in the body
        LoginResponse response = new LoginResponse(userDetails.getUsername() , roles , jwtToken );

        return ResponseEntity.ok(response);
    }

    // sign up
    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest request){

        // check username already exist and email already exist
        if ( userRepository.existsByUserName(request.getUsername())){
            return ResponseEntity.badRequest().body( new MessageResponse("Error: Username already exists "));
        }

        if ( userRepository.existsByEmail(request.getEmail())){
            return ResponseEntity.badRequest().body( new MessageResponse("Error: Email already exists "));
        }
        // create new user account
        User newUser = new User(request.getUsername() ,
                request.getEmail() ,
                passwordEncoder.encode(request.getPassword()));

        // set for roles
        Set<String> roles = request.getRole();
        Role role;

        // if roles is null or empty , throw exception
        if ( roles == null || roles.isEmpty() ){
            role = roleRepository.findByRoleName(AppRole.ROLE_USER).orElseThrow(
                    () -> new RuntimeException("Error: Role is not found")
            );
        }else {
            String roleStr = roles.iterator().next();
            if ( roles.equals("admin")){
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            // set userdetails
            newUser.setAccountNonLocked(true);
            newUser.setAccountNonExpired(true);
            newUser.setCredentialsNonExpired(true);
            newUser.setEnabled(true);
            newUser.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            newUser.setAccountExpiryDate(LocalDate.now().plusYears(1));
            newUser.setTwoFactorEnabled(false);
            newUser.setSignUpMethod("email");
        }

        // save with userrepository
        newUser.setRole(role);
        userRepository.save(newUser);

        emailService.sendUserRegistrationEmail(newUser.getEmail() , loginlink );

        return ResponseEntity.ok(new MessageResponse("user register successfully"));
    }

    // userdetails
    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(response);
    }

    @GetMapping("/username")
    public String currentUserName(@AuthenticationPrincipal UserDetails userDetails) {
        return (userDetails != null) ? userDetails.getUsername() : "";
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email ){

        try{
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok( new MessageResponse("Password reset email was sent !"));

        }catch ( Exception e ){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body( new MessageResponse("Error : send password reset email "));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token ,
                                           @RequestParam String newPassword ){

        try{
            userService.resetPassword( token , newPassword );
            return ResponseEntity.ok( new MessageResponse("Password Reset successfully"));
        }catch (Exception e){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse(e.getMessage()));
        }
    }

    @PostMapping("/enable-2fa")
    public ResponseEntity<?> enable2FA(){
        Long userId = authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);

        String qrCodeUrl = totpService.getQrCodeUrl( secret ,
                userService.getUserById(userId).getUserName() );

        return ResponseEntity.ok(qrCodeUrl);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<?> disable2FA(){
        Long userId = authUtil.loggedInUserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled");
    }


    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code) {
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }


    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null){
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }
    }


    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code,
                                                 @RequestParam String jwtToken) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

}