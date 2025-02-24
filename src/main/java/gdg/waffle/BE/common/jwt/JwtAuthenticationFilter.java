package gdg.waffle.BE.common.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenManager jwtTokenManager;

    public JwtAuthenticationFilter(JwtTokenManager jwtTokenManager) {
        this.jwtTokenManager = jwtTokenManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // ✅ 기존: Authorization 헤더 → 변경: 쿠키에서 Access Token 추출
        String token = jwtTokenManager.getTokenFromCookie(request, "accessToken");

        if (token != null && jwtTokenManager.validateToken(token, false)) { // ✅ Access Token 검증
            try {
                String username = jwtTokenManager.getUsername(token);

                // ✅ 기존 `List.of()` 제거 후 ROLE_USER 기본 권한 추가
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

                // ✅ Spring Security 인증 정보 설정
                var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                // ✅ JWT 검증 중 예외 발생 시 로그 남기기
                logger.error("JWT 검증 중 오류 발생 : ", e);
            }
        }

        // ✅ 필터 체인 계속 진행
        filterChain.doFilter(request, response);
    }
}

