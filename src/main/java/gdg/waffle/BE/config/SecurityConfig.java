package gdg.waffle.BE.config;

import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.CustomUserDetails;
import gdg.waffle.BE.login.service.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import com.google.firebase.auth.FirebaseAuth;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // REST API이므로 basic auth 및 csrf 보안을 사용하지 않음
                .httpBasic().disable()
                .csrf().disable()
                // JWT를 사용하기 때문에 세션을 사용하지 않음
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests()
                // 공개 API 설정
                .requestMatchers("/members/login", "/members/home", "/members/sign-up", "/members/check-id",
                        "/members/sign-in", "/members/social-sign-in", "/auth/google", "/auth/google/callback",
                        "/swagger-ui/**", "/v3/api-docs/**", "/webjars/**", "/custom-api-docs/**", "/resources/**",
                        "/members/me", "members/logout")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/users").permitAll() // 회원가입 요청

                // ✅테스트(차후에 작업해야됨)✅ 관리자 전용 API - ROLE_ADMIN만 접근 가능
                .requestMatchers("/members/admin").hasRole("ADMIN")

                // 상태가 ACTIVE인 사용자만 모든 요청 가능하도록 추가
                .anyRequest().access((authentication, request) -> {
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

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(MemberRepository memberRepository) {
        return new CustomUserDetailsService(memberRepository);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }
}
