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
public class MemberDto {

    private Long id;

    private String loginId;

    private String password;

    private String name;

    private String nickName;

    private LocalDate birth;

    private String phone;

    private String email;

    private String address; // 도로명 주소

    private String detailAddress;

    private List<String> roles;

    private String status;

    private LocalDateTime registrationDate;

    private LocalDateTime lastModified;

    // 회원가입 후 이름, 닉네임, 가입일자를 유저에게 보여줌
    static public MemberDto toDtoForSignUp(Member member) {
        return MemberDto.builder()
                .name(member.getName())
                .nickName(member.getNickName())
                .registrationDate(member.getRegistrationDate())
                .build();
    }

//    public Member toEntity() {
//        return Member.builder()
//                .id(id)
//                .loginId(loginId)
//                .name(name)
//                .nickName(nickName)
//                .birth(birth)
//                .phone(phone)
//                .email(email)
//                .address(address)
//                .detailAddress(detailAddress)
//                .status(status)
//                .registrationDate(registrationDate)
//                .lastModified(lastModified);
//    }
}