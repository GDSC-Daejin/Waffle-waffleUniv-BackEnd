package gdg.waffle.BE.login.service;

import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.config.GoogleOAuthProperties;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.repository.MemberRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class GoogleOAuthService {

    private final GoogleOAuthProperties googleOAuthProperties;
    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RestTemplate restTemplate = new RestTemplate();

    public GoogleOAuthService(GoogleOAuthProperties googleOAuthProperties,
                              MemberRepository memberRepository,
                              JwtTokenProvider jwtTokenProvider) {
        this.googleOAuthProperties = googleOAuthProperties;
        this.memberRepository = memberRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 🔹 Google 로그인 URL 생성
     */
    public String getGoogleLoginUrl() {
        return "https://accounts.google.com/o/oauth2/auth" +
                "?client_id=" + googleOAuthProperties.getClientId() +
                "&redirect_uri=" + googleOAuthProperties.getRedirectUri() +
                "&response_type=code" +
                "&scope=email profile";
    }

    /**
     * 🔹 Google OAuth 인증 코드 처리 후 JWT 발급
     */
    public RedirectView authenticateWithGoogle(String authCode) {
        // 1️⃣ Google에서 액세스 토큰 요청
        String tokenUrl = "https://oauth2.googleapis.com/token";
        Map<String, String> requestBody = Map.of(
                "code", authCode,
                "client_id", googleOAuthProperties.getClientId(),
                "client_secret", googleOAuthProperties.getClientSecret(),
                "redirect_uri", googleOAuthProperties.getRedirectUri(),
                "grant_type", "authorization_code"
        );

        Map<String, Object> response = restTemplate.postForObject(tokenUrl, requestBody, Map.class);
        String accessToken = (String) response.get("access_token");

        // 2️⃣ Google 사용자 정보 가져오기
        String userInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";
        Map<String, Object> userInfo = restTemplate.getForObject(userInfoUrl + "?access_token=" + accessToken, Map.class);

        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        String uid = (String) userInfo.get("sub");       // ✅ Google `sub` → `uid`

        var socialUserCount = memberRepository.countByIsSocialUser(true);  // 기존 소셜 유저 수 조회
        String generatedNickName = "소셜유저" + (socialUserCount + 1);  // 닉네임 생성

        // 3️⃣ DB에서 기존 회원 확인 후 저장
        var member = memberRepository.findByEmail(email).orElseGet(() -> {
            return memberRepository.save(Member.builder()
                    .email(email)
                    .name(name)  // ✅ Google 닉네임 저장
                    .uid(uid)             // ✅ Google UID 저장
                    .nickName(generatedNickName)
                    .isSocialUser(true)
                    .role(Member.Role.valueOf("USER"))
                    .status(Member.Status.valueOf("ACTIVE"))
                    .registrationDate(LocalDateTime.now())
                    .lastLoginAt(LocalDateTime.now())
                    .build());
        });

        // 기존 회원이라면 이름과 마지막 접속 날짜 업데이트
        if (!member.getNickName().equals(name)) {
            member = member.toBuilder()
                    .name(name)
                    .lastLoginAt(LocalDateTime.now())
                    .build();
            memberRepository.save(member);
        }

        // 4️⃣ JWT 발급 (generateTokenForSocialUser 사용)
        JwtToken jwtToken = jwtTokenProvider.generateTokenForSocialUser(member.getEmail(),
                "ROLE_" + member.getRole().name());

        // 5️⃣ JWT 포함하여 홈으로 리디렉트
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("http://localhost:8080/members/home?jwtToken=" + jwtToken);
        return redirectView;
    }
}
