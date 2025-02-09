package gdg.waffle.BE.login.domain;

import ch.qos.logback.core.status.Status;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Entity
@Table(name= "members")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder(toBuilder = true)
@EqualsAndHashCode(of = "id")
public class Member implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", updatable = false, unique = true, nullable = false)
    private Long id;

    @Column(unique = true, nullable = true, length = 50)
    private String uid; // 소셜 로그인 유저를 구별하기 위한 고유 ID

    @Column(unique = true, nullable = true, length = 50)
    private String loginId; // 일반 로그인 유저만 사용

    @Column(nullable = true)
    private String password; // 일반 로그인 유저만 사용

    @Column(nullable = true, length = 50)
    private String name; // 유저 이름

    @Column(nullable = false, length = 50)
    private String nickName; // 유저 닉네임

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

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Role role; // 역할 (USER, ADMIN)

    public enum Role {
        USER, ADMIN
    }

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Status status; // 유저 상태 (ACTIVE, BANNED, DELETED)

    public enum Status {
        ACTIVE, BANNED, DELETED
    }

    @Column(nullable = false)
    private boolean isSocialUser; // 소셜 로그인 여부

    @Column(nullable = false)
    private LocalDateTime registrationDate; // 가입 날짜

    @Column(nullable = false)
    private LocalDateTime lastLoginAt; // 마지막 접속 날짜

    @Override
    public String getUsername() {
        return loginId;
    }

    @Override
    public String getPassword() {
        return password;
    }

    //
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + this.role));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}