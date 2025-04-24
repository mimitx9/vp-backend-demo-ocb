package com.ccp.service;

import com.ccp.dto.TokenRequest;
import com.ccp.dto.TokenResponse;
import com.ccp.dto.UserInfoDto;
import com.ccp.model.Session;
import com.ccp.model.User;
import com.ccp.repository.SessionRepository;
import com.ccp.repository.UserRepository;
import com.ccp.util.CacheUtil;
import com.ccp.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final JwtUtil jwtUtil;
    private final CacheUtil cacheUtil;
    private final RestTemplate restTemplate;
    private final TokenService tokenService;

    @Value("${spring.security.oauth2.client.provider.ciam.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.ciam.user-info-uri}")
    private String userInfoUri;

    @Value("${spring.security.oauth2.client.registration.ciam.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.ciam.client-secret}")
    private String clientSecret;

    @Value("${cookie.session-token.name}")
    private String cookieName;

    @Value("${cookie.session-token.max-age}")
    private int cookieMaxAge;

    @Value("${cookie.secure}")
    private boolean cookieSecure;

    @Value("${cookie.http-only}")
    private boolean cookieHttpOnly;

    @Value("${cookie.domain}")
    private String cookieDomain;

    @Value("${cookie.path}")
    private String cookiePath;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Exchange authorization code for access token and user info
     */
    @Transactional
    public String handleAuthorizationCallback(String code, String redirectUri, HttpServletRequest request, HttpServletResponse response) {
        // Exchange code for token
        TokenResponse tokenResponse = exchangeCodeForToken(code, redirectUri);
        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            throw new RuntimeException("Failed to exchange code for token");
        }

        // Get user info from token
        UserInfoDto userInfo = getUserInfo(tokenResponse.getAccessToken());
        if (userInfo == null || userInfo.getPreferredUsername() == null) {
            throw new RuntimeException("Failed to get user info");
        }

        // Create user info object
        User userDetails = userRepository.findByUsername(userInfo.getPreferredUsername())
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(userInfo.getPreferredUsername());
                    newUser.setEmail(userInfo.getEmail());
                    newUser.setFirstName(userInfo.getGivenName());
                    newUser.setLastName(userInfo.getFamilyName());
                    return userRepository.save(newUser);
                });

        // Tạo session và lưu vào cơ sở dữ liệu
        String sessionToken = createSession(userDetails, tokenResponse, request);

        // Set cookie with session token
        setSessionCookie(response, sessionToken);

        // Store access token in cache for later use
        cacheUtil.storeAccessToken(userInfo.getPreferredUsername(), tokenResponse.getAccessToken());

        // Return redirect URL
        return "/dashboard";
    }

    /**
     * Exchange authorization code for access token
     */
    private TokenResponse exchangeCodeForToken(String code, String redirectUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUri, request, TokenResponse.class);
            log.debug("Token exchange response: {}", response.getStatusCode());
            log.info("Access token: {}", response.getBody().getAccessToken());
            return response.getBody();
        } catch (Exception e) {
            log.error("Error exchanging code for token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Get user info from access token
     */
    private UserInfoDto getUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);  // Đặt Bearer token vào header

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            // Sử dụng exchange thay vì getForEntity để có thể truyền headers
            ResponseEntity<UserInfoDto> response = restTemplate.exchange(
                    userInfoUri,
                    HttpMethod.GET,
                    entity,
                    UserInfoDto.class
            );

            log.debug("User info response: {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception e) {
            log.error("Error getting user info: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Create session for user
     */
    private String createSession(User user, TokenResponse tokenResponse, HttpServletRequest request) {
        // Generate a session token using JWT
        String sessionToken = jwtUtil.generateToken(user);

        // Calculate expiration time
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(tokenResponse.getExpiresIn());

        // Get client info
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        // Create session record
        Session session = Session.builder()
                .sessionId(UUID.randomUUID().toString())
                .user(user)
                .accessToken(tokenResponse.getAccessToken())
                .refreshToken(tokenResponse.getRefreshToken())
                .expiresAt(expiresAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .active(true)
                .build();

        sessionRepository.save(session);
        return sessionToken;
    }

    /**
     * Set session cookie in response
     */
    private void setSessionCookie(HttpServletResponse response, String sessionToken) {
        Cookie cookie = new Cookie(cookieName, sessionToken);
        cookie.setMaxAge(cookieMaxAge);
        cookie.setSecure(cookieSecure);
        cookie.setHttpOnly(cookieHttpOnly);
        cookie.setPath(cookiePath);

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);
    }

    /**
     * Get client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Validate session token
     */
    public boolean validateSessionToken(String token) {
        return jwtUtil.validateToken(token);
    }

    /**
     * Extract user ID from session token
     */
    public String extractUsernameFromToken(String token) {
        return jwtUtil.extractUsername(token);
    }

    /**
     * Logout user by invalidating session
     */
    @Transactional
    public void logout(String sessionToken, HttpServletResponse response) {
        if (sessionToken != null && jwtUtil.validateToken(sessionToken)) {
            String userId = jwtUtil.extractUsername(sessionToken);
            User user = userRepository.findByUsername(userId).orElse(null);
            if (user != null) {
                List<Session> activeSessions = sessionRepository.findByUserAndActiveTrue(user);
                for (Session session : activeSessions) {
                    String accessToken = session.getAccessToken();
                    String refreshToken = session.getRefreshToken();
                    if (accessToken != null && refreshToken != null) {
                        logoutFromKeycloak(accessToken, refreshToken); // Gửi cả refreshToken
                    }
                    session.setActive(false);
                    sessionRepository.save(session);
                }
            }

            cacheUtil.invalidateAccessToken(userId);

            Cookie cookie = new Cookie(cookieName, null);
            cookie.setMaxAge(0);
            cookie.setPath(cookiePath);

            if (cookieDomain != null && !cookieDomain.isEmpty()) {
                cookie.setDomain(cookieDomain);
            }

            response.addCookie(cookie);
        }
    }

    private void logoutFromKeycloak(String accessToken, String refreshToken) {
        try {
            // Lấy session từ accessToken
            Session session = sessionRepository.findByAccessTokenAndActiveTrue(accessToken);
            if (session == null || session.getRefreshToken() == null) {
                log.warn("No active session or refresh token found for access token: {}", accessToken);
                return;
            }
            refreshToken = session.getRefreshToken();

            String baseUrl = tokenUri.substring(0, tokenUri.lastIndexOf("/token"));
            String logoutUrl = baseUrl + "/logout";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("refresh_token", refreshToken); // Sử dụng refresh_token

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.postForEntity(logoutUrl, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("Successfully logged out from Keycloak. Response: {}", response.getBody());
            } else {
                log.warn("Failed to logout from Keycloak: {}. Response: {}", response.getStatusCode(), response.getBody());
            }
        } catch (Exception e) {
            log.error("Error logging out from Keycloak: {}", e.getMessage(), e);
        }
    }

    /**
     * Refresh user session
     */
    @Transactional
    public void refreshUserSession(String username, HttpServletRequest request, HttpServletResponse response) {
        User user = User.builder()
                .username(username)
                .build();

        String newSessionToken = jwtUtil.generateToken(user);

        setSessionCookie(response, newSessionToken);
    }
}