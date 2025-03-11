package gdg.waffle.BE.login.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
@Entity
@Table(name= "members")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder(toBuilder = true)
@EqualsAndHashCode(of = "id")
// 회원 정보를 저장하는 엔티티 클래스 (Spring Security의 UserDetails 구현)
public class Member implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 기본 키 자동 증가
    @Column(name = "member_id", updatable = false, unique = true, nullable = false)
    private Long id; // 회원 고유 ID

    @Column(unique = true, nullable = true, length = 50)
    private String uid; // 소셜 로그인 유저를 구별하기 위한 고유 ID

    @Column(unique = true, nullable = true, length = 50)
    private String loginId; // 일반 로그인 유저만 사용

    @Column(nullable = true)
    private String password; // 일반 로그인 유저만 사용

    @Column(nullable = true, length = 50)
    private String name; // 유저 이름

    @Column(nullable = false, length = 50)
    private String nickName; // 유저 닉네임(필수)

    @Column(nullable = true)
    private LocalDate birth; // 생년월일

    @Column(nullable = true, length = 20)
    private String phone; // 전화번호

    @Column(nullable = false, length = 100)
    private String email; // 소셜, 일반 로그인에 이메일은 필수

    @Column(nullable = true, length = 150)
    private String address; // 도로명 주소

    @Column(nullable = true, length = 100)
    private String detailAddress; // 상세 주소

    @Enumerated(EnumType.STRING) // Enum 값을 문자열 형태로 저장
    @Column(nullable = false, length = 10)
    private Role role; // 역할 (USER, ADMIN)

    public enum Role {
        USER, ADMIN
    }

    @Enumerated(EnumType.STRING) // Enum 값을 문자열 형태로 저장
    @Column(nullable = false, length = 10)
    private Status status; // 유저 상태
    public enum Status {
        ACTIVE, // 활성화
        DORMANT, // 휴면
        BANNED, // 정지
        DELETED // 탈퇴
    }

    @Column(nullable = false)
    private boolean isSocialUser; // 소셜 로그인 여부 (true: 소셜 로그인, false: 일반 로그인)

    @Column(nullable = false)
    private LocalDateTime registrationDate; // 가입 날짜

    @Column(nullable = false)
    private LocalDateTime lastLoginAt; // 마지막 접속 날짜

    // Spring Security의 UserDetails 구현 메서드
    @Override
    public String getUsername() {
        return loginId;
    } // Spring Security에서 사용자의 고유 아이디 반환

    @Override
    public String getPassword() {
        return password;
    } // Spring Security에서 사용자의 비밀번호 반환

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + this.role)); // 사용자의 권한 반환
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    } // 계정 만료 여부 (true: 만료되지 않음)

    @Override
    public boolean isAccountNonLocked() {
        return true;
    } // 계정 잠김 여부 (true: 잠기지 않음)

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    } // 비밀번호 만료 여부 (true: 만료되지 않음)

    @Override
    public boolean isEnabled() {
        return true;
    } // 계정 활성화 여부 (true: 활성화됨)
}