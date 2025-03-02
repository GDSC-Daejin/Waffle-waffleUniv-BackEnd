package gdg.waffle.BE.config;

import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.CustomUserDetails;
import gdg.waffle.BE.login.service.CustomUserDetailsService;
import gdg.waffle.BE.login.domain.Member.Status;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
// Spring Security 설정을 담당하는 클래스
public class SecurityConfig {

    // HTTP 요청에 대한 보안 필터 체인 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .httpBasic().disable()// 기본 인증 비활성화 (JWT 사용)
                .csrf().disable()// CSRF 보안 비활성화 (REST API)
                // JWT를 사용하기 때문에 세션을 사용하지 않음
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용 안함 (JWT 사용)
                .and()
                .authorizeHttpRequests()

                // 인증 없이 접근 가능한 경로 (permitAll)
                .requestMatchers(
                        "/members/sign-up", "/members/sign-in", "/members/check-id", "/members/home", "/members/login",
                        "/auth/google", "/auth/google/callback",
                        "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**", "/custom-api-docs/**", "/resources/**"
                ).permitAll()

                // 로그인한 사용자만 접근 가능 (authenticated)
                .requestMatchers(
                        "/members/me", "/members/logout", "/게시판 CRUD API"
                ).authenticated()

                // 특정 조건 (status가 ACTIVE) 만족하는 사용자만 접근 가능
                .requestMatchers(HttpMethod.POST, "/게시판 CRUD API")
                .access((authentication, request) -> {
                    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                    if (principal instanceof CustomUserDetails userDetails) {
                        return new AuthorizationDecision(userDetails.getStatus().equals(Status.ACTIVE));
                    }
                    return new AuthorizationDecision(false);
                })

                // 관리자 전용 API
                .requestMatchers("/게시판 CRUD API").hasRole("ADMIN")

                // JWT 토큰 검증이 반드시 필요한 API
                .requestMatchers("/게시판 CRUD API").authenticated()

                // 그 외 모든 요청은 차단
                .anyRequest().denyAll()

                .and()

                // 인증 실패 시 401 반환
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            response.getWriter().write("권한이 없습니다.");
                        })
                )
                .build();
    }

    // 비밀번호 암호화를 위한 BCryptPasswordEncoder 빈 설정
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 사용자 정보를 조회하는 UserDetailsService 빈 설정
    @Bean
    public UserDetailsService userDetailsService(MemberRepository memberRepository) {
        return new CustomUserDetailsService(memberRepository);
    }

    // 인증 관리자(AuthenticationManager) 설정
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // 인증 제공자(AuthenticationProvider) 설정
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
}
