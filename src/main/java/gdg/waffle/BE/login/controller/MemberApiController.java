package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.domain.*;
import gdg.waffle.BE.login.service.MemberService;
import gdg.waffle.BE.login.validation.ValidationSequence;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Tag(name = "MemberApiController", description = "유저 관련 API")
@RestController // REST API 컨트롤러로 설정
@RequiredArgsConstructor // 생성자 주입을 위한 Lombok 어노테이션
@RequestMapping("/members")
// 유저 관련 API를 제공하는 컨트롤러
public class MemberApiController {
    private final MemberService memberService;

    // 아이디 중복 확인
    @GetMapping("/check-id")
    @Operation(summary = "아이디 중복 확인", description = "회원가입 시, 유저가 입력한 아이디가 중복되는지 확인합니다.")
    public ResponseEntity<String> checkId(@RequestParam @NotBlank(message = "아이디를 입력해주세요.") String loginId) {
        memberService.checkId(loginId);
        return ResponseEntity.ok("사용 가능한 아이디입니다.");
    }

    // 회원가입
    @PostMapping("/sign-up")
    @Operation(summary = "유저 회원가입", description = "유저 정보를 입력받아 회원가입을 진행합니다.")
    public ResponseEntity<String> signUp(@RequestBody @Validated(ValidationSequence.class) SignUpDto signUpDto) {
        memberService.signUp(signUpDto);
        return ResponseEntity.status(HttpStatus.CREATED).body("회원가입이 완료되었습니다.");
    }

    // 일반 유저 로그인
    @PostMapping("/sign-in")
    @Operation(summary = "일반 유저 로그인", description = "일반 유저의 로그인을 진행합니다.")
    public ResponseEntity<String> signIn(@RequestBody @Valid SignInDto signInDto, HttpServletResponse response) {
        log.info("로그인 컨트롤러");
        memberService.signIn(signInDto, response);
        return ResponseEntity.ok("로그인 성공");
    }

    // 로그아웃
    @PostMapping("/logout")
    @Operation(summary = "유저 로그아웃", description = "유저의 로그아웃을 진행합니다. 동시에 JwtToken의 AccessToken과 RefreshToken을 모두 폐기합니다.")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        memberService.logout(request, response);
        return ResponseEntity.ok("로그아웃 완료");
    }

    // 로그인 상태 확인 API
    @GetMapping("/me")
    @Operation(summary = "로그인 상태 확인", description = "현재 로그인한 사용자의 정보를 반환합니다.")
    public ResponseEntity<String> getCurrentUser(HttpServletRequest request) {
        log.info("getCurrentUser 실행");
        memberService.getCurrentUser(request);
        return ResponseEntity.ok("로그인 상태 유지 중");
    }

    // Refresh Token으로 Access Token 재발급
    @PostMapping("/refresh-token")
    @Operation(summary = "refresh Token 재발급",
            description = "access Token이 만료됐을 시, refresh Token의 유효기간을 확인한 후 유효하다면 access Token을 재발급합니다.")
    public ResponseEntity<String> refreshAccessToken(HttpServletRequest request, HttpServletResponse response) {
        memberService.refreshAccessToken(request, response);
        return ResponseEntity.ok("새로운 Access Token 발급 완료");
    }
}