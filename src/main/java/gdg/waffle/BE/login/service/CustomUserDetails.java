package gdg.waffle.BE.login.service;

import gdg.waffle.BE.login.domain.Member;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
// Spring Security의 User 클래스를 확장하여 커스텀 유저 정보를 제공하는 클래스
public class CustomUserDetails extends User {

    private final Member.Status status; // 회원 상태 (ACTIVE, DORMANT, BANNED, DELETED)

    // 생성자 - Member 엔티티와 권한 정보를 받아서 부모 클래스(User)에 전달
    public CustomUserDetails(Member member, Collection<? extends GrantedAuthority> authorities) {
        super(member.getLoginId(), member.getPassword(), authorities);
        this.status = member.getStatus();
    }

    // 계정 상태가 ACTIVE인지 확인하는 메서드
    public boolean isActive() {
        return this.status == Member.Status.ACTIVE; // ✅ ACTIVE 상태인지 확인하는 메서드
    }
}
