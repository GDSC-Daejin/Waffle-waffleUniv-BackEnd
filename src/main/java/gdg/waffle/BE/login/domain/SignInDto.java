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

@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class, SignInDto.class})
@Getter
@Setter
@ToString
@NoArgsConstructor
public class SignInDto {

    @NotBlank(message = "로그인 ID는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 아이디 형식입니다.", regexp = "^[a-z0-9_-]{4,10}",
            groups = ValidationGroups.PatternGroup.class)
    private String loginId;

    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 비밀번호 형식입니다.",
            regexp = "^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[$@$!%*#?&])[A-Za-z0-9$@$!%*#?&]{8,15}$",
            groups = ValidationGroups.PatternGroup.class)
    private String password;

    @Builder
    public SignInDto(String loginId, String password) {
        this.loginId = loginId;
        this.password = password;
    }
}
