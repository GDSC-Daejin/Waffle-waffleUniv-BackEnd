package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Controller
@RequiredArgsConstructor
@RequestMapping("/members")
public class MemberViewController {
    private final MemberService memberService;

    @GetMapping("/login") // 로그인 페이지 이동
    public String loginPage() {
        return "login";
    }

    @GetMapping("/sign-up") // 회원가입 페이지 이동
    public String signUpPage() {
        return "sign-up";
    }

    @GetMapping("/home") // 홈화면 이동
    public String homePage() {
        return "home";
    }
}


