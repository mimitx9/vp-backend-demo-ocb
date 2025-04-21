package com.ccp.config;

import com.ccp.service.AuthService;
import com.ccp.service.TokenService;
import com.ccp.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthInterceptor implements HandlerInterceptor {

    private final JwtUtil jwtUtil;
    private final AuthService authService;

    @Value("${cookie.session-token.name}")
    private String cookieName;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Skip for authentication endpoints
        String requestPath = request.getServletPath();
        if (requestPath.startsWith("/auth/") || requestPath.equals("/auth")) {
            return true;
        }

        // Check session token
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    String sessionToken = cookie.getValue();

                    // Check if token is about to expire and refresh if needed
                    if (jwtUtil.validateToken(sessionToken)) {
                        if (jwtUtil.isTokenExpiringSoon(sessionToken)) {
                            try {
                                Long userId = jwtUtil.extractUserId(sessionToken);
                                authService.refreshUserSession(userId, request, response);
                                log.debug("Session refreshed for user: {}", userId);
                            } catch (Exception e) {
                                log.error("Failed to refresh session: {}", e.getMessage());
                            }
                        }
                        return true;
                    }
                    break;
                }
            }
        }

        // Continue with request processing (let security filter handle unauthorized access)
        return true;
    }
}