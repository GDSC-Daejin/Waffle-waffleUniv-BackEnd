package gdg.waffle.BE.common.firebase;


import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

// Firebase 초기화 클래스: 애플리케이션 시작 시 Firebase를 설정하고 인증 객체 제공
@Slf4j
@Configuration
public class FirebaseInitializer {

    // Firebase 애플리케이션 초기화
    @Bean
    public FirebaseApp firebaseApp() throws IOException {
        if (FirebaseApp.getApps().isEmpty()) { // FirebaseApp이 존재하지 않으면 초기화 진행
            FileInputStream serviceAccount =
                    new FileInputStream("src/main/resources/firebase.json"); // Firebase 서비스 계정 키 로드

            FirebaseOptions options = FirebaseOptions.builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))  // 인증 정보 설정
                    .setStorageBucket("heroku-sample.appspot.com") // Firebase 스토리지 버킷 설정
                    .build();

            FirebaseApp app = FirebaseApp.initializeApp(options); // Firebase 앱 초기화
            log.info("FirebaseApp initialized: " + app.getName()); // 초기화 완료 로그 출력
            return app;
        }
        return FirebaseApp.getInstance(); // 이미 초기화된 경우 기존 FirebaseApp 반환
    }

    // Firebase 인증 객체 생성
    @Bean
    public FirebaseAuth getFirebaseAuth(FirebaseApp firebaseApp) {
        return FirebaseAuth.getInstance(firebaseApp);
    }
}

