package gdg.waffle.BE.login.controller;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import gdg.waffle.BE.login.repository.MemberRepository;
import gdg.waffle.BE.login.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberApiController {
    private final MemberService memberService;
    private final FirebaseAuth firebaseAuth;
    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;

    // 회원가입
    @PostMapping("/sign-up")
    public ResponseEntity<String> signUp(@RequestBody SignUpDto signUpDto) {
        try {
            memberService.signUp(signUpDto);
            return ResponseEntity.ok("회원가입이 완료되었습니다.");
        } catch (IllegalArgumentException e) {
            log.error("회원가입 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body("회원가입 실패: " + e.getMessage());
        } catch (Exception e) {
            log.error("서버 오류: {}", e.getMessage());
            return ResponseEntity.status(500).body("서버 오류로 인해 회원가입에 실패했습니다.");
        }
    }

    // 일반 로그인
    @PostMapping("/sign-in")
    public JwtToken signIn(@RequestBody SignInDto signInDto) {
        String loginId = signInDto.getLoginId();
        String password = signInDto.getPassword();

        log.info("로그인 아이디 : {}", loginId);
        log.info("로그인 비밀번호 : {}", password);

        JwtToken jwtToken = memberService.signIn(signInDto);
        log.info("request username = {}, password = {}", loginId, password);
        log.info("jwtToken accessToken = {}, refreshToken = {}", jwtToken.getAccessToken(), jwtToken.getRefreshToken());
        return jwtToken;
    }

    // 소셜 로그인
    @PostMapping("/social-login")
    public ResponseEntity<?> socialLogin(@RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Firebase ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Authorization header");
        }

        String idToken = authorizationHeader.substring(9);

        try {
            FirebaseToken decodedToken = firebaseAuth.verifyIdToken(idToken);
            String email = decodedToken.getEmail();
            String name = decodedToken.getName();
            String phone = (String) decodedToken.getClaims().get("phone_number");
            String address = (String) decodedToken.getClaims().get("address");

            log.info("Firebase 사용자 이메일: {}", email);
            log.info("Firebase 사용자 이름: {}", name);
            log.info("Firebase 사용자 전화번호: {}", phone);
            log.info("Firebase 사용자 주소: {}", address);

            var member = memberRepository.findByEmail(email).orElseGet(() ->
                    memberRepository.save(Member.builder()
                            .email(email)
                            .name(name)
                            .phone(phone)
                            .address(address)
                            .isSocialUser(true)
                            .role(Member.Role.USER)
                            .status(Member.Status.ACTIVE)
                            .registrationDate(LocalDateTime.now())
                            .lastLoginAt(LocalDateTime.now())
                            .build())
            );

            // JWT 생성 (소셜 로그인 전용 메서드 사용)
            JwtToken jwtToken = jwtTokenProvider.generateTokenForSocialUser(
                    member.getEmail(),
                    "ROLE_" + member.getRole().name()
            );

            return ResponseEntity.ok(jwtToken);

        } catch (FirebaseAuthException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("유효하지 않은 Firebase ID 토큰");
        }
    }

//    @PostMapping("/test")
//    public String test() {
//        return "success";
//    }

}