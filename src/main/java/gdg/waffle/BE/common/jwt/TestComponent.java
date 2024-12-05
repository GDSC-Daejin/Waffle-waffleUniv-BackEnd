package gdg.waffle.BE.common.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class TestComponent {
    public TestComponent(@Value("${jwt.secret}") String secret) {
        System.out.println("JWT Secret: " + secret); // 읽은 값을 출력
    }
}