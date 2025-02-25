package gdg.waffle.BE.common.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

// JWT 토큰을 담는 DTO 클래스: 클라이언트에게 Access Token과 Refresh Token을 반환할 때 사용
@Builder
@Data
@AllArgsConstructor
public class JwtToken {
    private String grantType;// 인증 타입 (예: "Bearer")
    private String accessToken; // 액세스 토큰 (JWT)
    private String refreshToken; // 리프레시 토큰 (JWT)
}