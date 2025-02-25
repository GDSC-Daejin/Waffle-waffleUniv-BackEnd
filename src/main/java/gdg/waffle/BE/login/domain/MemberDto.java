package gdg.waffle.BE.login.domain;

import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Builder
// 회원 정보를 다룰 DTO 클래스
public class MemberDto {

    private Long id; // 회원 고유 ID

    private String loginId; // 로그인 아이디

    private String password; // 비밀번호

    private String name; // 이름

    private String nickName; // 닉네임

    private LocalDate birth; // 생년월일

    private String phone; // 전화번호

    private String email; // 이메일 (소셜 및 일반 로그인 공통)

    private String address; // 도로명 주소

    private String detailAddress; // 상세 주소

    private List<String> roles; // 역할 (USER, ADMIN)

    private String status; // 회원 상태 (ACTIVE, DORMANT, BANNED, DELETED)

    private LocalDateTime registrationDate; // 가입 날짜

    private LocalDateTime lastModified; // 마지막 수정 날짜

    // 회원가입 후 이름, 닉네임, 가입일자만 포함된 DTO 반환
    static public MemberDto toDtoForSignUp(Member member) {
        return MemberDto.builder()
                .name(member.getName())
                .nickName(member.getNickName())
                .registrationDate(member.getRegistrationDate())
                .build();
    }
}