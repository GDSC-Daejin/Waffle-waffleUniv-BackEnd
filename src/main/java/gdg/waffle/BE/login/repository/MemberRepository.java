package gdg.waffle.BE.login.repository;

import gdg.waffle.BE.login.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// 회원 정보를 조회하는 JPA Repository
public interface MemberRepository extends JpaRepository<Member, Long> {
    // 로그인 아이디로 유저 정보 조회 (Optional로 반환)
    Optional<Member> findByLoginId(String loginId);

    // 이메일을 기반으로 유저 정보 조회 (Optional로 반환)
    Optional<Member> findByEmail(String email);

    // 아이디 중복 확인
    boolean existsByLoginId(String loginId);

    // 닉네임 중복 확인
    boolean existsByNickName(String nickName);

    // 이메일 중복 확인
    boolean existsByEmail(String email);

    // 현재 등록된 소셜 로그인 유저의 수 반환
    long countByIsSocialUser(boolean isSocialUser);
}