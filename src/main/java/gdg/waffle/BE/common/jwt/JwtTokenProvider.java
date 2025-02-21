package gdg.waffle.BE.common.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {
    private final Key key;

    // application.yml에서 secret 값 가져와서 key에 저장
    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // ✅ JWT 발급 & 쿠키 저장 (AccessToken + RefreshToken)
    public void generateTokenAndSetCookie(HttpServletResponse response, Authentication authentication) {
        long now = System.currentTimeMillis();

        // ✅ Access Token (1시간 유효)
        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .setExpiration(new Date(now + 3600000)) // 1시간 유효
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // ✅ Refresh Token (24시간 유효)
        String refreshToken = Jwts.builder()
                .setExpiration(new Date(now + 86400000)) // 24시간 유효
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // ✅ HTTP-Only 쿠키 설정 (보안 강화)
        setCookie(response, "accessToken", accessToken, 3600);  // 1시간
        setCookie(response, "refreshToken", refreshToken, 86400);  // 24시간
    }

    // ✅ Refresh Token 기반으로 Access Token 재발급
    public String refreshAccessToken(String refreshToken) {
        if (!validateToken(refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token");
        }

        String username = getUsername(refreshToken);
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(username)
                .setExpiration(new Date(now + 3600000)) // 1시간 유효
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
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

    public boolean validateToken(String token) {
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