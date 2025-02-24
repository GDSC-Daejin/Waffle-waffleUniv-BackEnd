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
public class MemberServiceImpl implements MemberService {
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenManager jwtTokenManager;
    private final PasswordEncoder passwordEncoder; // 올바른 passwordEncoder 사용

    // 로그인
    @Transactional
    @Override
    public void signIn(SignInDto signInDto, HttpServletResponse response) {
        log.info("로그인 서비스 시작");
        // ID 기반으로 회원 정보 조회
        Member member = memberRepository.findByLoginId(signInDto.getLoginId())
                .orElseThrow(() -> new IllegalArgumentException("존재하는 아이디가 없습니다."));

        // 비밀번호 검증
        if (!passwordEncoder.matches(signInDto.getPassword(), member.getPassword())) {
            log.error("비밀번호 불일치! 입력된 비밀번호: {}, 암호화된 비밀번호: {}", signInDto.getPassword(), member.getPassword());
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
        log.info("비밀번호 검증까지완료");

        try {
            // 1️⃣ AuthenticationToken 생성
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(signInDto.getLoginId(), signInDto.getPassword());
            log.info("AuthenticationToken 생성 : {}", authenticationToken);

            // 2️⃣ 인증 수행 (검증)
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            log.info("Authentication 생성 : {}", authentication);

            // 3️⃣ JWT 발급 후 쿠키에 저장
            jwtTokenManager.generateTokenAndSetCookie(response, authentication);
            log.info("JWT 발급 후 쿠키 저장완료");
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

    // ✅ 로그아웃 (Refresh Token 삭제 + 쿠키 삭제)
    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtTokenManager.getTokenFromCookie(request, "refreshToken");

        if (refreshToken != null) {
            String username = jwtTokenManager.getUsername(refreshToken);
            jwtTokenManager.deleteRefreshToken(username); // ✅ Redis에서 Refresh Token 삭제
        }

        // ✅ 쿠키 삭제
        jwtTokenManager.setCookie(response, "accessToken", null, 0);
        jwtTokenManager.setCookie(response, "refreshToken", null, 0);
    }

    // ✅ Refresh Token을 이용한 Access Token 재발급
    @Transactional
    public void refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtTokenManager.getTokenFromCookie(request, "refreshToken");

        if (refreshToken == null) {
            throw new RuntimeException("Refresh Token이 존재하지 않습니다.");
        }

        String username = jwtTokenManager.getUsername(refreshToken);

        // ✅ Redis + JWT 자체 검증
        if (!jwtTokenManager.validateRefreshToken(username, refreshToken)) {
            throw new RuntimeException("유효하지 않은 Refresh Token");
        }

        // ✅ 새 Access Token & Refresh Token 생성
        Map<String, String> newTokens = jwtTokenManager.generateTokens(username);

        // ✅ Redis에 새로운 Refresh Token 저장
        jwtTokenManager.storeRefreshToken(username, newTokens.get("refreshToken"));

        log.info("✅ 새로운 AccessToken 발급: {}", newTokens.get("accessToken"));
        log.info("✅ 새로운 RefreshToken 발급: {}", newTokens.get("refreshToken"));

        // ✅ 새 토큰을 쿠키에 저장
        jwtTokenManager.setCookie(response, "accessToken", newTokens.get("accessToken"), 3600);
        jwtTokenManager.setCookie(response, "refreshToken", newTokens.get("refreshToken"), 86400);
    }

    // ✅ 아이디 중복 확인
    @Transactional
    @Override
    public void checkId(String loginId) {
        if (memberRepository.existsByLoginId(loginId)) {
            throw new IllegalArgumentException("이미 사용 중인 ID 입니다.");
        }
    }

    // ✅ 로그인한 유저의 토큰이 유효한지 검사
    public void getCurrentUser(HttpServletRequest request) {
        String accessToken = jwtTokenManager.getTokenFromCookie(request, "accessToken");

        if (accessToken == null || !jwtTokenManager.validateToken(accessToken, false)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다.");
        }
    }
}