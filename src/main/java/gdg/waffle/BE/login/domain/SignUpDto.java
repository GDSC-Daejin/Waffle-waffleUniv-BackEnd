package gdg.waffle.BE.login.domain;

import gdg.waffle.BE.login.validation.ValidationGroups;
import jakarta.validation.GroupSequence;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class, SignUpDto.class})
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class SignUpDto {

    // 아이디 - 최소 4 ~ 15 글자 제한, 영소문자, 숫자, -_(특수문자)만 허용
    @NotBlank(message = "로그인 ID는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 아이디 형식입니다.", regexp = "^[a-z0-9_-]{4,15}", groups = ValidationGroups.PatternGroup.class)
    private String loginId;

    // 비밀번호 - 영문자, 숫자, 특수문자 각 최소 하나씩 포함돼야 함
    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 비밀번호 형식입니다.", regexp = "^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[$@$!%*#?&])[A-Za-z0-9$@$!%*#?&]{8,15}$",
            groups = ValidationGroups.PatternGroup.class)
    private String password;

    @NotBlank(message = "이름은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String name;

    @NotBlank(message = "닉네임은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String nickName;

    private LocalDate birth;

    private String phone;

    @NotBlank(message = "이메일은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Email(message = "잘못된 이메일 형식입니다.")
    private String email;

    private String address;

    private String detailAddress;

    private List<String> roles;

    private String status;

    private LocalDateTime registrationDate;

    private LocalDateTime lastModified;

    public Member toEntity(String encodedPassword) {
        return Member.builder()
                .loginId(loginId)
                .password(encodedPassword)
                .name(name)
                .nickName(nickName)
                .birth(birth)
                .phone(phone)
                .email(email)
                .address(address)
                .detailAddress(detailAddress)
                .role(Member.Role.valueOf("USER"))
                .status(Member.Status.valueOf("ACTIVE"))
                .isSocialUser(false)
                .registrationDate(LocalDateTime.now())
                .lastLoginAt(LocalDateTime.now())
                .build();
    }
}
