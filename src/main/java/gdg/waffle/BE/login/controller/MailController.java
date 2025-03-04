package gdg.waffle.BE.login.controller;

import gdg.waffle.BE.login.domain.EmailCheckDto;
import gdg.waffle.BE.login.domain.EmailRequestDto;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.service.MemberService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.Check;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import gdg.waffle.BE.login.service.MailSendService;


@Slf4j
@RestController
@RequiredArgsConstructor
public class MailController {
    private final MailSendService mailService;
    private final MemberService memberService;

    @PostMapping("/mailSend")
    public ResponseEntity<String> mailSend(@RequestBody @Valid EmailRequestDto emailDto) {
        // ✅ 이메일 중복 확인
        if (memberService.checkEmail(emailDto.getEmail())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("⚠️ 이미 가입된 이메일입니다.");
        }

        // ✅ 이메일이 중복되지 않으면 인증번호 전송
        mailService.joinEmail(emailDto.getEmail());
        return ResponseEntity.ok("✅ 인증번호가 이메일로 발송되었습니다.");
    }

    @PostMapping("/mailauthCheck")
    public Boolean AuthCheck(@RequestBody @Valid EmailCheckDto emailCheckDto) {
        boolean Checked = mailService.CheckAuthNum(emailCheckDto.getEmail(), emailCheckDto.getAuthNum());
        if (Checked) {
            return true;
        } else {
            throw new NullPointerException("이메일 인증에 실패하였습니다. 올바른 인증번호를 입력해주세요");
        }
    }
}