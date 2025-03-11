package gdg.waffle.BE.login.domain;

import gdg.waffle.BE.login.validation.ValidationGroups;
import jakarta.validation.GroupSequence;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

// 유효성 검사 순서를 정의 (NotBlank → Pattern 순으로 실행)
@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class, SignInDto.class})
@Getter // 필드에 대한 Getter 자동 생성
@Setter // 필드에 대한 Setter 자동 생성
@ToString // 객체를 문자열로 변환할 때 toString() 자동 생성
@NoArgsConstructor // 기본 생성자 자동 생성
// 로그인 요청을 처리하기 위한 DTO 클래스
public class SignInDto {

    @NotBlank(message = "로그인 ID는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String loginId;

    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String password;

    @Builder
    public SignInDto(String loginId, String password) {
        this.loginId = loginId;
        this.password = password;
    }
}
