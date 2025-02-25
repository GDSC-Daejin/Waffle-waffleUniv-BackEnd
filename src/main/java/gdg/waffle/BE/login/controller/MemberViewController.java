package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Tag(name = "MemberViewController", description = "유저 관련 홈페이지 이동 API")
@Controller
@RequiredArgsConstructor
@RequestMapping("/members")
// 유저 관련 페이지 이동을 처리하는 컨트롤러
public class MemberViewController {

    @GetMapping("/login") // 로그인 페이지 이동
    @Operation(summary = "일반 유저 로그인 페이지 이동", description = "일반 유저의 로그인 페이지로 이동합니다.")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/sign-up") // 회원가입 페이지 이동
    @Operation(summary = "일반 유저 회원가입 페이지 이동", description = "일반 유저의 회원가입 페이지로 이동합니다.")
    public String signUpPage() {
        return "sign-up";
    }

    @GetMapping("/home") // 홈화면 이동
    @Operation(summary = "홈 화면 이동", description = "홈 화면으로 이동합니다.")
    public String homePage() {
        return "home";
    }
}


