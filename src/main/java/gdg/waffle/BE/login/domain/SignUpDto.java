package gdg.waffle.BE.login.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpDto {

    private String loginId;

    private String password;

    private String name;

    private String nickName;

    private LocalDate birth;

    private String phone;

    private String email;

    private String address;

    private String detailAddress;

    private List<String> roles;

    private String status;

    private LocalDateTime registrationDate;

    private LocalDateTime lastModified;

    public Member toEntity(String encodedPassword, List<String> roles) {
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
                .roles(roles)
                .status("ACTIVE")
                .registrationDate(LocalDateTime.now())
                .lastModified(LocalDateTime.now())
                .build();
    }
}
