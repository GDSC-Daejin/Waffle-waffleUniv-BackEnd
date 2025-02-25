package gdg.waffle.BE.config;

import com.google.firebase.auth.FirebaseAuth;
import gdg.waffle.BE.common.firebase.FirebaseTokenFilter;
import gdg.waffle.BE.common.jwt.JwtAuthenticationFilter;
import gdg.waffle.BE.common.jwt.JwtTokenManager;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Configuration
@Component
// 필터 설정 클래스: Firebase 및 JWT 인증 필터를 등록하고 API 경로별로 적용 순서를 설정
public class FilterConfig {
    private final UserDetailsService userDetailsService;
    private final FirebaseAuth firebaseAuth;
    private final JwtTokenManager jwtTokenManager;

    // 필터 설정을 위한 의존성 주입
    public FilterConfig(UserDetailsService userDetailsService, FirebaseAuth firebaseAuth, JwtTokenManager jwtTokenManager) {
        this.userDetailsService = userDetailsService;
        this.firebaseAuth = firebaseAuth;
        this.jwtTokenManager = jwtTokenManager;
    }

    // FirebaseTokenFilter를 소셜 로그인 관련 API에서만 실행되도록 설정
    @Bean
    public FilterRegistrationBean<FirebaseTokenFilter> firebaseFilterRegistration() {
        FilterRegistrationBean<FirebaseTokenFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new FirebaseTokenFilter(userDetailsService, firebaseAuth));

        // Firebase 인증 필터 적용 경로 (Google 소셜 로그인 API 전용)
        registrationBean.addUrlPatterns("/auth/google/*", "/auth/google/callback");

        // 필터 실행 순서 지정 (낮을수록 먼저 실행됨) - Firebase 필터가 1순위
        registrationBean.setOrder(1);

        return registrationBean;
    }

    // JwtAuthenticationFilter를 인증이 필요한 API에서만 실행되도록 설정
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration() {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new JwtAuthenticationFilter(jwtTokenManager));

        // JWT 인증이 필요한 API 경로 설정 (보호할 엔드포인트 추가 필요)
        registrationBean.addUrlPatterns("/members/아무거나");

        // 필터 실행 순서 지정 (Firebase 필터보다 뒤에 실행됨)
        registrationBean.setOrder(2);

        return registrationBean;
    }
}


