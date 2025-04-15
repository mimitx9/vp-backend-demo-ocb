package com.ocb.controller;

import com.ocb.dto.AuthRequest;
import com.ocb.dto.AuthResponse;
import com.ocb.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    /**
     * Verify user credentials
     */
    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verifyCredentials(@Valid @RequestBody AuthRequest request) {
        log.info("Received authentication request for user: {}", request.getUsername());
        AuthResponse response = authService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("OCB Auth Service is up and running!");
    }
}