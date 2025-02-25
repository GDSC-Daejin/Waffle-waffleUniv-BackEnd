package gdg.waffle.BE.login.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Tag(name = "AdminApiController", description = "관리자 전용 API")
@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
// 관리자 전용 API를 제공하는 컨트롤러
public class AdminController {

    @GetMapping("/test")
    @Operation(summary = "관리자 테스트 페이지", description = "관리자만 접근 가능한 페이지입니다.")
    public ResponseEntity<String> adminDashboard() {
        return ResponseEntity.ok("관리자 전용 페이지입니다.");
    }
}
