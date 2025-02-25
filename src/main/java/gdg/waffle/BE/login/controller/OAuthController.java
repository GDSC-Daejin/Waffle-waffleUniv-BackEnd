package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.service.GoogleOAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "OAuthController", description = "소셜 로그인 관련 API")
@RestController
@RequestMapping("/auth")
// Google OAuth를 이용한 소셜 로그인을 처리하는 컨트롤러
public class OAuthController {

    private final GoogleOAuthService googleOAuthService;

    // 생성자 주입을 통해 GoogleOAuthService 사용
    public OAuthController(GoogleOAuthService googleOAuthService) {
        this.googleOAuthService = googleOAuthService;
    }

    // Google 로그인 페이지 이동
    @GetMapping("/google")
    @Operation(summary = "소셜 유저 로그인 페이지 이동", description = "소셜 유저 로그인 페이지에서 로그인 진행 후 결과를 반환해줍니다.")
    public ResponseEntity<?> redirectToGoogleLogin() {
        String googleAuthUrl = googleOAuthService.getGoogleLoginUrl() + "&prompt=consent"; // Google 로그인 페이지 URL 생성

        return ResponseEntity.status(HttpStatus.FOUND) // 302 Redirect 응답 반환
                .header(HttpHeaders.LOCATION, googleAuthUrl) // Google 로그인 페이지로 리다이렉트
                .build();
    }

    // Google 로그인 후 콜백을 처리하고 JWT 발급 후 홈 화면으로 이동
    @GetMapping("/google/callback")
    @Operation(summary = "소셜 유저 JWT 발급", description = "소셜 유저에게 JWT를 발급해준 후 홈 화면으로 이동합니다.")
    public RedirectView handleGoogleCallback(@RequestParam("code") String authCode, HttpServletResponse response) {
        return googleOAuthService.authenticateWithGoogle(authCode, response); // Google OAuth 인증 처리 후 홈 화면으로 리다이렉트
    }
}
