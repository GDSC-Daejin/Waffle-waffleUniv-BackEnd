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

// 유효성 검사 순서 설정 (NotBlank → Pattern → SignUpDto 순으로 실행)
@GroupSequence({ValidationGroups.NotBlankGroup.class, ValidationGroups.PatternGroup.class, SignUpDto.class})
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Data
// 회원가입 요청을 처리하는 DTO 클래스
public class SignUpDto {

    // 로그인 ID - 4~15자, 영소문자, 숫자, 특수문자(-, _) 허용
    @NotBlank(message = "로그인 ID는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 아이디 형식입니다.", regexp = "^[a-zA-Z0-9_-]{4,15}", groups = ValidationGroups.PatternGroup.class)
    private String loginId;

    // 비밀번호 - 8~20자, 영문자, 숫자, 특수문자 최소 하나 포함
    @NotBlank(message = "비밀번호는 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Pattern(message = "잘못된 비밀번호 형식입니다.", regexp = "^(?=.*[A-Za-z])(?=.*[0-9])(?=.*[$@$!%*#?&])[A-Za-z0-9$@$!%*#?&]{8,20}$",
            groups = ValidationGroups.PatternGroup.class)
    private String password;

    @NotBlank(message = "이름은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String name; // 사용자 이름

    @NotBlank(message = "닉네임은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    private String nickName; // 닉네임

    private LocalDate birth; // 생년월일

    private String phone; // 전화번호

    @NotBlank(message = "이메일은 필수 입력 항목입니다.", groups = ValidationGroups.NotBlankGroup.class)
    @Email(message = "잘못된 이메일 형식입니다.")
    private String email; // 이메일 (필수)

    private String address; // 도로명 주소

    private String detailAddress; // 상세 주소

    private List<String> roles; // 역할 (USER, ADMIN)

    private String status; // 유저 상태 (ACTIVE, DORMANT, BANNED, DELETED)

    private LocalDateTime registrationDate; // 가입 날짜

    private LocalDateTime lastModified; // 마지막 수정 날짜

    // DTO를 엔티티로 변환하는 메서드
    public Member toEntity(String encodedPassword) {
        return Member.builder()
                .loginId(loginId)
                .password(encodedPassword) // 비밀번호는 암호화된 값으로 저장
                .name(name)
                .nickName(nickName)
                .birth(birth)
                .phone(phone)
                .email(email)
                .address(address)
                .detailAddress(detailAddress)
                .role(Member.Role.valueOf("USER")) // 기본 역할 USER 설정
                .status(Member.Status.valueOf("ACTIVE")) // 기본 상태 ACTIVE 설정
                .isSocialUser(false) // 기본적으로 일반 회원가입 유저로 설정
                .registrationDate(LocalDateTime.now()) // 현재 가입 시간 저장
                .lastLoginAt(LocalDateTime.now()) // 가입 시 마지막 로그인 시간을 현재 시간으로 설정
                .build();
    }
}
