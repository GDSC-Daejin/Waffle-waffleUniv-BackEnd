package gdg.waffle.BE.config;

import com.google.firebase.auth.FirebaseAuth;
import gdg.waffle.BE.common.firebase.FirebaseTokenFilter;
import gdg.waffle.BE.common.jwt.JwtAuthenticationFilter;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
public class FilterConfig {
    private final UserDetailsService userDetailsService;
    private final FirebaseAuth firebaseAuth;
    private final JwtTokenProvider jwtTokenProvider;

    public FilterConfig(UserDetailsService userDetailsService, FirebaseAuth firebaseAuth, JwtTokenProvider jwtTokenProvider) {
        this.userDetailsService = userDetailsService;
        this.firebaseAuth = firebaseAuth;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    // ✅ FirebaseTokenFilter를 소셜 로그인 관련 API에서만 실행되도록 설정
    @Bean
    public FilterRegistrationBean<FirebaseTokenFilter> firebaseFilterRegistration() {
        FilterRegistrationBean<FirebaseTokenFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new FirebaseTokenFilter(userDetailsService, firebaseAuth));

        // ✅ 소셜 로그인 API에서만 실행됨
        registrationBean.addUrlPatterns("/auth/google/*", "/auth/google/callback");

        // ✅ 필터 실행 순서 (낮을수록 먼저 실행됨)
        registrationBean.setOrder(1);

        return registrationBean;
    }

    // ✅ JwtAuthenticationFilter를 인증이 필요한 API에서만 실행되도록 설정
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration() {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new JwtAuthenticationFilter(jwtTokenProvider));

        // ✅ JWT 인증이 필요한 API 경로만 필터 적용 (추가 필요)
        registrationBean.addUrlPatterns("/members/추가 필요");

        // ✅ 필터 실행 순서 (Firebase 필터보다 뒤에 실행됨)
        registrationBean.setOrder(2);

        return registrationBean;
    }
}


