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

// JWT 인증 필터 클래스: 요청에서 쿠키로부터 JWT를 추출해 인증을 처리하고 SecurityContext에 저장
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenManager jwtTokenManager; // JWT 토큰을 관리하는 객체

    public JwtAuthenticationFilter(JwtTokenManager jwtTokenManager) {
        this.jwtTokenManager = jwtTokenManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 쿠키에서 Access Token 추출 (기존 Authorization 헤더 방식에서 변경)
        String token = jwtTokenManager.getTokenFromCookie(request, "accessToken");

        // 토큰이 존재하고 유효한지 검증
        if (token != null && jwtTokenManager.validateToken(token, false)) { // ✅ Access Token 검증
            try {
                String username = jwtTokenManager.getUsername(token); // 토큰에서 사용자명 추출

                // 사용자 권한 설정 (기본값: ROLE_USER)
                List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

                // Spring Security 인증 정보 생성 및 컨텍스트에 저장
                var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);

            } catch (Exception e) {
                logger.error("JWT 검증 중 오류 발생 : ", e);
            }
        }

        // ✅ 필터 체인 계속 진행
        filterChain.doFilter(request, response);
    }
}

