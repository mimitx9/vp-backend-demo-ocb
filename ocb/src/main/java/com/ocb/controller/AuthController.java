package com.ocb.controller;

import com.ocb.dto.AuthRequest;
import com.ocb.dto.AuthResponse;
import com.ocb.dto.UserProfileDto;
import com.ocb.security.JwtUtil;
import com.ocb.service.AuthService;
import com.ocb.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserService userService;


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Xác thực username/password với Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );
            // Sinh token nếu xác thực thành công
            String token = jwtUtil.generateToken(loginRequest.getUsername());
            TokenResponse tokenResponse = new TokenResponse();
            tokenResponse.setToken(token);
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(@RequestParam String username) {
        try {
            UserProfileDto profile = userService.getUserProfile(username);
            return ResponseEntity.ok(profile);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OCB Auth Service is up and running!");
    }
}