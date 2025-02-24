package gdg.waffle.BE.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class JwtTokenManager {
    private final Key key;
    private final StringRedisTemplate redisTemplate;

    // 전역변수
    private static final long ACCESS_TOKEN_EXPIRATION = 3600000; // 1시간
    private static final long REFRESH_TOKEN_EXPIRATION = 86400000; // 24시간
    private static final String REFRESH_TOKEN_PREFIX = "refreshToken:";

    // application.yml에서 secret 값 가져와서 key에 저장
    public JwtTokenManager(@Value("${jwt.secret}") String secretKey, StringRedisTemplate redisTemplate) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
        this.redisTemplate = redisTemplate;
    }

    // ✅ JWT 발급 & 쿠키 저장 (AccessToken + RefreshToken)
    public void generateTokenAndSetCookie(HttpServletResponse response, Authentication authentication) {
        log.info("generateTokenAndSetCookie 실행");
        String username = authentication.getName();

        // ✅ Access Token & Refresh Token 생성
        Map<String, String> tokens = generateTokens(username);
        log.info("tokens 생성 : {}", tokens);

        // ✅ Refresh Token을 Redis에 저장
        storeRefreshToken(username, tokens.get("refreshToken"));
        log.info("Refresh Token을 Redis에 저장");

        // ✅ HTTP-Only 쿠키 설정 (보안 강화)
        setCookie(response, "accessToken", tokens.get("accessToken"), (int) (ACCESS_TOKEN_EXPIRATION / 1000));
        setCookie(response, "refreshToken", tokens.get("refreshToken"), (int) (REFRESH_TOKEN_EXPIRATION / 1000));
        log.info("토큰 쿠키저장 완료");

        log.info("AccessToken 발급 성공: {}", tokens.get("accessToken"));
        log.info("RefreshToken 발급 성공: {}", tokens.get("refreshToken"));
    }

    // ✅ Refresh Token 기반으로 Access Token 재발급
//    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
//        String refreshToken = getTokenFromCookie(request, "refreshToken");
//
//        if (refreshToken == null) {
//            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
//        }
//
//        String username = getUsername(refreshToken);
//
//        // ✅ Redis + JWT 자체 검증
//        if (!validateRefreshToken(username, refreshToken)) {
//            throw new RuntimeException("유효하지 않은 Refresh Token");
//        }
//
//        // ✅ 새 Access Token & Refresh Token 생성
//        Map<String, String> newTokens = generateTokens(username);
//
//        // ✅ Redis에 새로운 Refresh Token 저장
//        storeRefreshToken(username, newTokens.get("refreshToken"));
//
//        log.info("새로운 AccessToken 발급: {}", newTokens.get("accessToken"));
//        log.info("새로운 RefreshToken 발급: {}", newTokens.get("refreshToken"));
//
//        setCookie(response, "accessToken", newTokens.get("accessToken"), (int) (ACCESS_TOKEN_EXPIRATION / 1000));
//        setCookie(response, "refreshToken", newTokens.get("refreshToken"), (int) (REFRESH_TOKEN_EXPIRATION / 1000));
//    }

    // AccessToken, RefreshToken 생성
    public Map<String, String> generateTokens(String username) {
        long now = System.currentTimeMillis();

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", createToken(username, now, ACCESS_TOKEN_EXPIRATION));
        tokens.put("refreshToken", createToken(username, now, REFRESH_TOKEN_EXPIRATION));

        return tokens;
    }

    // JWT 토큰 생성
    private String createToken(String username, long now, long expirationTime) {
        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(now + expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ✅ Refresh Token을 Redis에 저장
    public void storeRefreshToken(String username, String refreshToken) {
        redisTemplate.opsForValue().set(REFRESH_TOKEN_PREFIX + username, refreshToken, REFRESH_TOKEN_EXPIRATION, TimeUnit.MILLISECONDS);
    }

    // ✅ Redis에서 Refresh Token 검증
    public boolean validateRefreshToken(String username, String refreshToken) {
        String storedToken = redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + username);

        // ✅ Redis에 저장된 값이 없거나 다르면 실패
        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return false;
        }

        // ✅ Refresh Token 자체가 유효한지 확인
        return validateToken(refreshToken, true);
    }

    // ✅ 로그아웃 시 Refresh Token 삭제
    public void deleteRefreshToken(String username) {
        redisTemplate.delete(REFRESH_TOKEN_PREFIX + username);
    }

    // ✅ 쿠키에서 JWT 추출
    public String getTokenFromCookie(HttpServletRequest request, String tokenName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (tokenName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    // 토큰이 유효한지 검증
    public boolean validateToken(String token, boolean isRefreshToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.error("Invalid JWT Token: {}", e.getMessage());
            return false;
        }
    }

    // ✅ 토큰에서 사용자명 추출
    public String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    // ✅ 쿠키 설정 메서드 (중복 제거)
    public void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }
}