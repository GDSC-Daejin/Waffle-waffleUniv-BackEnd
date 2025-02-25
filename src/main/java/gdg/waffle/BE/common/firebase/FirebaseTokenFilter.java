package gdg.waffle.BE.common.firebase;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.NoSuchElementException;

// Firebase 인증 필터 클래스: Firebase에서 발급한 JWT 토큰을 검증하고 인증 처리를 수행
public class FirebaseTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(FirebaseTokenFilter.class);
    private final UserDetailsService userDetailsService; // Spring Security의 사용자 정보 서비스
    private final FirebaseAuth firebaseAuth; // Firebase 인증 객체

    public FirebaseTokenFilter(UserDetailsService userDetailsService, FirebaseAuth firebaseAuth) {
        this.userDetailsService = userDetailsService;
        this.firebaseAuth = firebaseAuth;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization"); // Authorization 헤더에서 토큰 가져오기

        if (header != null && header.startsWith("Bearer ")) { // Bearer 토큰인지 확인
            String token = header.substring(7); // "Bearer " 이후의 실제 토큰 값 추출
            try {
                FirebaseToken decodedToken = firebaseAuth.verifyIdToken(token); // Firebase 토큰 검증
                UserDetails userDetails = userDetailsService.loadUserByUsername(decodedToken.getUid()); // UID 기반으로 사용자 정보 조회
                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()); // 인증 객체 생성
                SecurityContextHolder.getContext().setAuthentication(authentication); // Spring Security 컨텍스트에 인증 정보 저장
            } catch (FirebaseAuthException e) {
                logger.error("Firebase 인증 실패: {}", e.getMessage()); // 인증 실패 로그 출력
                response.setStatus(HttpStatus.SC_UNAUTHORIZED); // 401 Unauthorized 응답 반환
                response.getWriter().write("Unauthorized - Invalid Firebase Token"); // 에러 메시지 응답
                return;
            }
        }

        filterChain.doFilter(request, response); // 다음 필터 실행
    }
}
