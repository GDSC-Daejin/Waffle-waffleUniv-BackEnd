package gdg.waffle.BE.login.controller;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.domain.*;
import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.MemberService;
import gdg.waffle.BE.login.validation.ValidationSequence;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Slf4j
@Tag(name = "MemberApiController", description = "유저 관련 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberApiController {
    private final MemberService memberService;

    // 아이디 중복 확인
    @GetMapping("/check-id")
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

    // 일반 로그인
    @PostMapping("/sign-in")
    @Operation(summary = "일반 유저 로그인", description = "일반 유저의 로그인을 진행합니다.")
    public ResponseEntity<JwtToken> signIn(@RequestBody @Validated(ValidationSequence.class) SignInDto signInDto) {
        return ResponseEntity.ok(memberService.signIn(signInDto));
    }
}