package gdg.waffle.BE.login.service;

import gdg.waffle.BE.login.domain.Member;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class CustomUserDetails extends User {

    private final Member.Status status; // ✅ 추가된 필드

    public CustomUserDetails(Member member, Collection<? extends GrantedAuthority> authorities) {
        super(member.getLoginId(), member.getPassword(), authorities);
        this.status = member.getStatus();
    }

    public boolean isActive() {
        return this.status == Member.Status.ACTIVE; // ✅ ACTIVE 상태인지 확인하는 메서드
    }
}
