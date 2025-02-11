package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.service.GoogleOAuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
public class OAuthController {

    private final GoogleOAuthService googleOAuthService;

    public OAuthController(GoogleOAuthService googleOAuthService) {
        this.googleOAuthService = googleOAuthService;
    }

    // Google 로그인 페이지 이동
    @GetMapping("/google")
    @Operation(summary = "소셜 유저 로그인 페이지 이동", description = "소셜 유저 로그인 페이지에서 로그인 진행 후 결과를 반환해줍니다.")
    public ResponseEntity<?> redirectToGoogleLogin() {
        String googleAuthUrl = googleOAuthService.getGoogleLoginUrl() + "&prompt=consent"; // 로그인 화면

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, googleAuthUrl)
                .build();
    }

    // 소셜 유저 JWT 발급 후 홈화면 이동
    @GetMapping("/google/callback")
    @Operation(summary = "소셜 유저 JWT 발급", description = "소셜 유저에게 JWT를 발급해준 후 홈 화면으로 이동합니다.")
    public RedirectView handleGoogleCallback(@RequestParam("code") String authCode) {
        return googleOAuthService.authenticateWithGoogle(authCode);
    }
}
