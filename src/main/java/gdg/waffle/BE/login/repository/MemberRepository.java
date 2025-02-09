package gdg.waffle.BE.login.repository;

import gdg.waffle.BE.login.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByLoginId(String loginId); // 로그인 아이디로 유저 정보 반환

    Optional<Member> findByEmail(String email); // UID 기반 유저 조회

    boolean existsByLoginId(String loginId); // 로그인 아이디로 유저 유무 반환

    long countByIsSocialUser(boolean isSocialUser); // 현재 등록된 소셜 유저 수 조회
}