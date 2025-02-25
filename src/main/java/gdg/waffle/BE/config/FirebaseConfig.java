package gdg.waffle.BE.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

@Configuration
// Firebase 설정 클래스: Firebase 인증을 위한 FirebaseAuth 빈을 생성
public class FirebaseConfig {

    // Firebase 인증 관리 객체(FirebaseAuth) 생성
    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp) {
        return FirebaseAuth.getInstance(firebaseApp);
    }

}
