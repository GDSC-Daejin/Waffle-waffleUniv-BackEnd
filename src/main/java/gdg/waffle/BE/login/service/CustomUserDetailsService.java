package gdg.waffle.BE.login.service;

import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.login.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
// Spring Security에서 사용자 인증을 처리하는 서비스 클래스
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository; // 회원 정보를 조회하는 JPA Repository

    @Override
    public UserDetails loadUserByUsername(String loginId) throws UsernameNotFoundException {
        // 로그인 아이디를 기반으로 회원 정보를 조회, 없으면 예외 발생
        Member member = memberRepository.findByLoginId(loginId)
                .orElseThrow(() -> new UsernameNotFoundException("해당하는 회원을 찾을 수 없습니다."));

        // 계정이 ACTIVE 상태가 아니면 로그인 불가
        if (member.getStatus() != Member.Status.ACTIVE) {
            throw new UsernameNotFoundException("해당 계정은 활성화되지 않았습니다.");
        }

        return createUserDetails(member); // Spring Security의 UserDetails 객체 생성
    }

    // Member 엔티티를 Spring Security의 UserDetails 객체로 변환
    private UserDetails createUserDetails(Member member) {
        return new CustomUserDetails(member, List.of(new SimpleGrantedAuthority("ROLE_" + member.getRole())));
    }


}