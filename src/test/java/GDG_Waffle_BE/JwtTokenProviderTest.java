//package GDG_Waffle_BE;
//
//import org.junit.jupiter.api.Test;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.boot.test.context.SpringBootTest;
//
//import static org.junit.jupiter.api.Assertions.assertNotNull;
//
//@SpringBootTest // Spring Boot 테스트 환경 설정
//public class JwtTokenProviderTest {
//
//    @Value("${jwt.secret}") // application.yml에서 jwt.secret 값 읽기
//    private String secret;
//
//    @Test
//    void testJwtSecretLoading() {
//        System.out.println("JWT Secret: " + secret); // 콘솔에 출력
//        assertNotNull(secret, "JWT secret 값이 null입니다!"); // 값이 null이 아니어야 성공
//    }
//}
