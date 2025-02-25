package gdg.waffle.BE.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
// Google OAuth 설정 값을 주입받아 관리하는 클래스
public class GoogleOAuthProperties {

    @Value("${google.client-id}") // application.yml에서 Google Client ID 값 주입
    private String clientId;

    @Value("${google.client-secret}") // application.yml에서 Google Client Secret 값 주입
    private String clientSecret;

    @Value("${google.redirect-uri}") // application.yml에서 Google Redirect URI 값 주입
    private String redirectUri;


    // Google Client ID 반환
    public String getClientId() {
        return clientId;
    }

    // Google Client Secret 반환
    public String getClientSecret() {
        return clientSecret;
    }

    // Google Redirect URI 반환
    public String getRedirectUri() {
        return redirectUri;
    }
}

