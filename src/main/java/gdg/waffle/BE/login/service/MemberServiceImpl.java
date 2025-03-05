package gdg.waffle.BE.login.service;

import gdg.waffle.BE.common.jwt.JwtTokenManager;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import gdg.waffle.BE.login.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
// 회원 관련 비즈니스 로직을 처리하는 서비스 클래스
public class MemberServiceImpl implements MemberService {

    private final MemberRepository memberRepository; // 회원 정보를 다루는 JPA Repository
    private final AuthenticationManager authenticationManager; // Spring Security 인증 관리자
    private final JwtTokenManager jwtTokenManager; // JWT 발급 및 관리
    private final PasswordEncoder passwordEncoder; // 비밀번호 암호화 및 검증

    // 로그인
    @Transactional
    @Override
    public void signIn(SignInDto signInDto, HttpServletResponse response) {

        // 아이디로 회원 조회, 없으면 예외 발생
        Member member = memberRepository.findByLoginId(signInDto.getLoginId())
                .orElseThrow(() -> new IllegalArgumentException("존재하는 아이디가 없습니다."));

        // 비밀번호 검증
        if (!passwordEncoder.matches(signInDto.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        try {
            // AuthenticationToken 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(signInDto.getLoginId(), signInDto.getPassword());

            // 인증 수행 (검증)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // JWT 발급 후 쿠키에 저장
            jwtTokenManager.generateTokenAndSetCookie(response, authentication);
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

    // 로그아웃 (Refresh Token 삭제 + 쿠키 삭제)
    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtTokenManager.getTokenFromCookie(request, "refreshToken");

        if (refreshToken != null) {
            String username = jwtTokenManager.getUsername(refreshToken);
            jwtTokenManager.deleteRefreshToken(username); // ✅ Redis에서 Refresh Token 삭제
        }

        // 쿠키 삭제
        jwtTokenManager.setCookie(response, "accessToken", null, 0);
        jwtTokenManager.setCookie(response, "refreshToken", null, 0);
    }

    // Refresh Token을 이용한 Access Token 재발급
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtTokenManager.getTokenFromCookie(request, "refreshToken");

        if (refreshToken == null) {
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }

        String username = jwtTokenManager.getUsername(refreshToken);

        // Redis 및 JWT 자체 검증
        if (!jwtTokenManager.validateRefreshToken(username, refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token");
        }

        // 새 Access Token 및 Refresh Token 생성
        Map<String, String> newTokens = jwtTokenManager.generateTokens(username);

        // Redis에 새로운 Refresh Token 저장
        jwtTokenManager.storeRefreshToken(username, newTokens.get("refreshToken"));

        // 새 토큰을 쿠키에 저장
        jwtTokenManager.setCookie(response, "accessToken", newTokens.get("accessToken"), 3600);
        jwtTokenManager.setCookie(response, "refreshToken", newTokens.get("refreshToken"), 86400);
    }

    // 아이디 중복 확인
    @Transactional
    @Override
    public boolean checkId(String loginId) {
        return memberRepository.existsByLoginId(loginId);
    }

    // 닉네임 중복 확인
    @Transactional
    @Override
    public boolean checkNick(String nickName) {
        return memberRepository.existsByNickName(nickName);
    }

    // 이메일 중복 확인
    @Transactional
    @Override
    public boolean checkEmail(String email) {
        return memberRepository.existsByEmail(email);
    }

    // 로그인한 유저의 토큰이 유효한지 검사
    public void getCurrentUser(HttpServletRequest request) {
        String accessToken = jwtTokenManager.getTokenFromCookie(request, "accessToken");

        if (accessToken == null || !jwtTokenManager.validateToken(accessToken, false)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
    }
}