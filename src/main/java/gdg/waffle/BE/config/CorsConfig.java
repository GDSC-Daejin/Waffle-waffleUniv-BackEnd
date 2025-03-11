package gdg.waffle.BE.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true); // 쿠키 허용
        config.setAllowedOrigins(List.of("http://localhost:3000")); // React 프론트엔드 도메인 허용
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); // 허용할 HTTP 메서드
        config.setAllowedHeaders(List.of("*")); // 모든 헤더 허용
        config.setExposedHeaders(List.of("Authorization", "Set-Cookie")); // 클라이언트에서 쿠키 접근 가능하도록 설정
        config.setMaxAge(3600L); // 1시간 동안 preflight 요청을 캐시하도록 설정

        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);
    }
}
