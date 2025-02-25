package gdg.waffle.BE.login.service;

import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;

// 회원 관련 기능을 정의하는 서비스 인터페이스
public interface MemberService {

    // 사용자의 아이디와 비밀번호로 로그인을 처리하고 JWT 토큰을 반환
    void signIn(SignInDto signInDto, HttpServletResponse response);

    // 새로운 회원을 등록
    void signUp(SignUpDto signUpDto);

    // 사용자의 로그아웃을 처리하고 JWT 토큰을 폐기
    void logout(HttpServletRequest request, HttpServletResponse response);

    // 주어진 로그인 ID가 이미 존재하는지 확인
    void checkId(String loginId);

    // Refresh Token을 사용하여 새로운 Access Token을 발급
    void refreshAccessToken(HttpServletRequest request, HttpServletResponse response);

    // 현재 로그인한 사용자의 정보를 반환
    void getCurrentUser(HttpServletRequest request);
    }

