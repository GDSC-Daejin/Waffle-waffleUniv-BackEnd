package gdg.waffle.BE.login.service;

import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

public interface MemberService {
    /**
     * 사용자의 아이디와 비밀번호로 로그인을 처리하고 JWT 토큰을 반환.
     * @param signInDto 로그인 정보 (username, password 포함)
     * @return 생성된 JWT 토큰
     */
    void signIn(SignInDto signInDto, HttpServletResponse response);
    void signUp(SignUpDto signUpDto);
    void checkId(String loginId);
    void refreshAccessToken(HttpServletRequest request, HttpServletResponse response);
    void getCurrentUser(HttpServletRequest request);
    }

