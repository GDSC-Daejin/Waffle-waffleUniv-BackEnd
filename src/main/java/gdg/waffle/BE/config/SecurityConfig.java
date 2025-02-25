package gdg.waffle.BE.config;

import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.CustomUserDetails;
import gdg.waffle.BE.login.service.CustomUserDetailsService;
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

//                // ✅ 인증 없이 접근 가능한 경로 (permitAll())
//                .requestMatchers("/", "/home", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
//                .requestMatchers("/auth/**").permitAll() // 로그인, 회원가입, 소셜 로그인 등
//                .requestMatchers(HttpMethod.POST, "/users").permitAll() // 회원가입
//
//                // ✅ 특정 권한이 필요한 경로 (hasRole, hasAuthority)
//                .requestMatchers("/admin/**").hasRole("ADMIN") // 관리자 전용 API
//                .requestMatchers(HttpMethod.POST, "/posts").hasAuthority("ROLE_USER") // 특정 권한 필요
//
//                // ✅ 그 외 모든 요청은 인증 필요
//                .anyRequest().authenticated()
//                .and()

                // 공개 API 설정
                .requestMatchers("/members/login", "/members/home", "/members/sign-up", "/members/check-id",
                        "/members/sign-in", "/members/social-sign-in", "/auth/google", "/auth/google/callback",
                        "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**", "/custom-api-docs/**", "/resources/**",
                        "/members/me", "members/logout", "members/refresh-token")
                .permitAll() // 인증 없이 접근 허용되는 URL 패턴
                .requestMatchers(HttpMethod.POST, "/users").permitAll() // 회원가입 요청 허용
                // ✅테스트(차후에 작업해야됨)✅ 관리자 전용 API - ROLE_ADMIN만 접근 가능
                .requestMatchers("/members/admin").hasRole("ADMIN") // 관리자 전용 API - ROLE_ADMIN만 접근 가능
                .anyRequest().access((authentication, request) -> {
                    // 로그인된 사용자의 상태가 ACTIVE인지 확인 후 접근 결정
                    Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
                    if (principal instanceof CustomUserDetails userDetails) {
                        return new AuthorizationDecision(userDetails.isActive()); // 유저가 ACTIVE 상태인지 확인
                    }
                    return new AuthorizationDecision(false); // 나머진 모두 false로 접근 제한
                })
                .and()

                // 인증 실패 시 401 반환
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            try {
                                response.getWriter().write("권한이 없습니다.");
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
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
