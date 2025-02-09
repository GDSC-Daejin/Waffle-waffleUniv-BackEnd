package gdg.waffle.BE.config;

import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import com.google.firebase.auth.FirebaseAuth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsService userDetailsService; // Firebase 인증 관련
    private final FirebaseAuth firebaseAuth;

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
                .requestMatchers("/members/login").permitAll() // 로그인 페이지 이동
                .requestMatchers("/members/home").permitAll() // 홈 화면 이동
                .requestMatchers("/members/sign-up").permitAll() // 회원가입
                .requestMatchers("/members/sign-in").permitAll() // 로그인
                .requestMatchers("/members/social-sign-in").permitAll() // 소셜 로그인
                .requestMatchers("/auth/google").permitAll() // 소셜 로그인
                .requestMatchers("/auth/google/callback").permitAll() // 소셜 로그인
                .requestMatchers(HttpMethod.POST, "/users").permitAll() // 회원가입 요청
                .requestMatchers("/resources/**").permitAll() // 정적 리소스
                // 인증된 사용자만 접근 가능한 요청 설정
                .anyRequest().authenticated()
                .and()
                // 인증 실패 시 401 반환
                .exceptionHandling()
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                .and().build();
    }

//    @Bean
//    public passwordEncoder passwordEncoder() {
//        // BCrypt Encoder 사용
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

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
