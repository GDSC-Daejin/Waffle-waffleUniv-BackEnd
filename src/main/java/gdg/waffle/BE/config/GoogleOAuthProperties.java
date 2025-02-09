package gdg.waffle.BE.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

@Component
public class GoogleOAuthProperties {

    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.client-secret}")
    private String clientSecret;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    @PostConstruct
    public void init() {
        System.out.println("🔹 Google Client ID: " + clientId);
        System.out.println("🔹 Google Client Secret: " + clientSecret);
        System.out.println("🔹 Google Redirect URI: " + redirectUri);
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}

