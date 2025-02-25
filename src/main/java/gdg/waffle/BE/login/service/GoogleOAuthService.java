package gdg.waffle.BE.login.service;

import gdg.waffle.BE.config.GoogleOAuthProperties;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.common.jwt.JwtTokenManager;
import gdg.waffle.BE.login.repository.MemberRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Service
// Google OAuth 인증을 처리하는 서비스 클래스
public class GoogleOAuthService {

    private final GoogleOAuthProperties googleOAuthProperties;// Google OAuth 설정 정보
    private final MemberRepository memberRepository; // 회원 정보 조회 및 저장을 위한 JPA Repository
    private final JwtTokenManager jwtTokenManager; // JWT 발급 및 관리
    private final RestTemplate restTemplate = new RestTemplate(); // HTTP 요청을 위한 RestTemplate 객체

    // 생성자 주입 방식으로 의존성 주입
    public GoogleOAuthService(GoogleOAuthProperties googleOAuthProperties,
                              MemberRepository memberRepository,
                              JwtTokenManager jwtTokenManager) {
        this.googleOAuthProperties = googleOAuthProperties;
        this.memberRepository = memberRepository;
        this.jwtTokenManager = jwtTokenManager;
    }

    // Google 로그인 URL 생성
    public String getGoogleLoginUrl() {
        return "https://accounts.google.com/o/oauth2/auth" +
                "?client_id=" + googleOAuthProperties.getClientId() +
                "&redirect_uri=" + googleOAuthProperties.getRedirectUri() +
                "&response_type=code" +
                "&scope=email profile";
    }

    // Google OAuth 인증 코드 처리 후 JWT 발급
    public RedirectView authenticateWithGoogle(String authCode, HttpServletResponse response) {
        // Google에서 액세스 토큰 요청
        String tokenUrl = "https://oauth2.googleapis.com/token";
        Map<String, String> requestBody = Map.of(
                "code", authCode,
                "client_id", googleOAuthProperties.getClientId(),
                "client_secret", googleOAuthProperties.getClientSecret(),
                "redirect_uri", googleOAuthProperties.getRedirectUri(),
                "grant_type", "authorization_code"
        );

        // 여기서 사용하는 accessToken은 Google API 호출을 위한 accessToken임 (JWT 아님)
        Map<String, Object> tokenResponse = restTemplate.postForObject(tokenUrl, requestBody, Map.class);
        String accessToken = (String) tokenResponse.get("access_token");

        // Google 사용자 정보 가져오기
        String userInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";
        Map<String, Object> userInfo = restTemplate.getForObject(userInfoUrl + "?access_token=" + accessToken, Map.class);

        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        String uid = (String) userInfo.get("sub"); // Google `sub` → `uid`

        var socialUserCount = memberRepository.countByIsSocialUser(true); // 현재 등록된 소셜 유저 수 조회
        String generatedNickName = "소셜유저" + (socialUserCount + 1); // 새로운 닉네임 생성

        // DB에서 기존 회원 확인 후 저장
        var member = memberRepository.findByEmail(email).orElseGet(() -> {
            return memberRepository.save(Member.builder()
                    .email(email)
                    .name(name)  // Google 닉네임 저장
                    .uid(uid) // Google UID 저장
                    .nickName(generatedNickName) // 기본 닉네임 설정
                    .isSocialUser(true) // 소셜 로그인 사용자 여부 설정
                    .role(Member.Role.valueOf("USER")) // 기본 권한 USER 설정
                    .status(Member.Status.valueOf("ACTIVE")) // 계정 상태 ACTIVE로 설정
                    .registrationDate(LocalDateTime.now()) // 가입 날짜 저장
                    .lastLoginAt(LocalDateTime.now()) // 마지막 로그인 시간 저장
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

        // JWT 발급
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, null, List.of());
        jwtTokenManager.generateTokenAndSetCookie(response, authentication);

        // JWT 포함하여 홈으로 리디렉트
        RedirectView redirectView = new RedirectView();
        redirectView.setUrl("http://localhost:8080/members/home");
        return redirectView;
    }
}
