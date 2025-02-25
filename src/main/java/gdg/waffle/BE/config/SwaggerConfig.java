package gdg.waffle.BE.config;

import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components()) // OpenAPI의 컴포넌트 설정 (추후 보안, 인증 관련 설정 가능)
                .info(new Info()
                        .title("GoStock API") // API 문서 제목 설정
                        .description("GoStock 서비스의 API 문서입니다.") // API 문서 설명
                        .version("1.0.0")); // API 버전 설정
    }
}