package com.ocb.service;

import com.ocb.dto.AuthRequest;
import com.ocb.dto.AuthResponse;
import com.ocb.model.User;
import com.ocb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${password.max-age-days}")
    private int passwordMaxAgeDays;

    /**
     * Authenticate user with credentials
     */
    @Transactional
    public AuthResponse authenticate(AuthRequest request) {
        String username = request.getUsername();
        String password = request.getPassword();

        log.debug("Authenticating user: {}", username);

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            log.debug("User not found: {}", username);
            return AuthResponse.builder()
                    .authenticated(false)
                    .message("Invalid credentials")
                    .errorCode("INVALID_CREDENTIALS")
                    .build();
        }

        User user = userOpt.get();

        if (user.isAccountLocked()) {
            log.debug("Account locked for user: {}", username);
            return AuthResponse.builder()
                    .authenticated(false)
                    .message("Account is locked. Please contact support.")
                    .errorCode("ACCOUNT_LOCKED")
                    .build();
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return AuthResponse.builder()
                    .authenticated(false)
                    .message("Invalid credentials")
                    .errorCode("INVALID_CREDENTIALS")
                    .build();
        }

        int passwordAgeDays = calculatePasswordAge(user);

        log.debug("Authentication successful for user: {}, password age: {} days", username, passwordAgeDays);

        return AuthResponse.builder()
                .authenticated(true)
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .passwordAgeDays(passwordAgeDays)
                .message("Authentication successful")
                .build();
    }

    /**
     * Calculate password age in days
     */
    private int calculatePasswordAge(User user) {
        LocalDateTime lastPasswordChange = user.getLastPasswordChange();
        if (lastPasswordChange == null) {
            lastPasswordChange = user.getCreatedAt();
        }

        long daysBetween = ChronoUnit.DAYS.between(lastPasswordChange, LocalDateTime.now());
        return (int) daysBetween;
    }
}