package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.service.GoogleOAuthService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class OAuthController {

    private final GoogleOAuthService googleOAuthService;

    public OAuthController(GoogleOAuthService googleOAuthService) {
        this.googleOAuthService = googleOAuthService;
    }

    /**
     * 🔹 Google 로그인 페이지로 리디렉트
     */
    @GetMapping("/google")
    public ResponseEntity<?> redirectToGoogleLogin() {
//        String googleAuthUrl = googleOAuthService.getGoogleLoginUrl();
        String googleAuthUrl = googleOAuthService.getGoogleLoginUrl() + "&prompt=consent"; // ✅ 로그인 화면 강제 표시

        return ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, googleAuthUrl)
                .build();
    }

    /**
     * 🔹 Google OAuth Callback → JWT 발급 후 홈으로 리디렉트
     */
    @GetMapping("/google/callback")
    public RedirectView handleGoogleCallback(@RequestParam("code") String authCode) {
        return googleOAuthService.authenticateWithGoogle(authCode);
    }
}
