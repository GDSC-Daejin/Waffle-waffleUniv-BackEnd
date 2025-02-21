package gdg.waffle.BE.login.service;

import ch.qos.logback.classic.encoder.JsonEncoder;
import com.google.firebase.auth.AbstractFirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import gdg.waffle.BE.login.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class MemberServiceImpl implements MemberService {
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder; // 올바른 passwordEncoder 사용

    @Transactional
    @Override
    public void signIn(SignInDto signInDto, HttpServletResponse response) {
        // ID 기반으로 회원 정보 조회
        Member member = memberRepository.findByLoginId(signInDto.getLoginId())
                .orElseThrow(() -> new IllegalArgumentException("존재하는 아이디가 없습니다."));

        // 비밀번호 검증
        if (!passwordEncoder.matches(signInDto.getPassword(), member.getPassword())) {
            log.error("비밀번호 불일치! 입력된 비밀번호: {}, 암호화된 비밀번호: {}", signInDto.getPassword(), member.getPassword());
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        try {
            // 1️⃣ AuthenticationToken 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(signInDto.getLoginId(), signInDto.getPassword());

            // 2️⃣ 인증 수행 (검증)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 3️⃣ JWT 발급 후 쿠키에 저장
            jwtTokenProvider.generateTokenAndSetCookie(response, authentication);
        } catch (Exception e) {
            throw new RuntimeException("로그인에 실패하였습니다. 관리자에게 문의해주세요.");
        }
    }

    // 일반유저 회원가입
    @Transactional
    @Override
    public void signUp(SignUpDto signUpDto) {

        // 아이디와 이메일 중복 확인
        if (memberRepository.existsByLoginId(signUpDto.getLoginId()) ||
                memberRepository.findByEmail(signUpDto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 ID 또는 이메일입니다.");
        }

        // Password 암호화
        String encodedPassword = passwordEncoder.encode(signUpDto.getPassword());

        try {
            memberRepository.save(signUpDto.toEntity(encodedPassword));
        } catch (Exception e) {
            throw new RuntimeException("회원 가입에 실패하였습니다. 관리자에게 문의해주세요.");
        }
    }

    // ✅ Refresh Token을 이용한 Access Token 재발급
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtTokenProvider.getTokenFromCookie(request, "refreshToken"   );

        if (refreshToken == null || !jwtTokenProvider.validateToken(refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token");
        }

        String newAccessToken = jwtTokenProvider.refreshAccessToken(refreshToken);
        jwtTokenProvider.setCookie(response, "accessToken", newAccessToken, 3600); // 1시간 유효
    }

    // 아이디 중복 확인
    @Transactional
    @Override
    public void checkId(String loginId) {
        if (memberRepository.existsByLoginId(loginId)) {
            throw new IllegalArgumentException("이미 사용 중인 ID 입니다.");
        }
    }

    public void getCurrentUser(HttpServletRequest request) {
        String accessToken = jwtTokenProvider.getTokenFromCookie(request, "accessToken");

        if (accessToken == null || !jwtTokenProvider.validateToken(accessToken)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
    }
}