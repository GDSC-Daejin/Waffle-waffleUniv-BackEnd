package gdg.waffle.BE.login.domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@NoArgsConstructor
public class SignInDto {
    private String loginId;
    private String password;

    @Builder
    public SignInDto(String loginId, String password) {
        this.loginId = loginId;
        this.password = password;
    }
}
