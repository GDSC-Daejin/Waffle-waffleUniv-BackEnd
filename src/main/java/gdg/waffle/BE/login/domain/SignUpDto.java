package gdg.waffle.BE.login.domain;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
public class SignUpDto {

    @NotBlank(message = "로그인 ID는 필수 입력 항목입니다.")
    private String loginId;

    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.")
    private String password;

    @NotBlank(message = "이름은 필수 입력 항목입니다.")
    private String name;

    private String nickName;

    private LocalDate birth;

    private String phone;

    @NotBlank(message = "이메일은 필수 입력 항목입니다.")
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
