package gdg.waffle.BE.login.service;

import ch.qos.logback.classic.encoder.JsonEncoder;
import com.google.firebase.auth.AbstractFirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import gdg.waffle.BE.common.jwt.JwtToken;
import gdg.waffle.BE.common.jwt.JwtTokenProvider;
import gdg.waffle.BE.login.domain.Member;
import gdg.waffle.BE.login.domain.MemberDto;
import gdg.waffle.BE.login.domain.SignInDto;
import gdg.waffle.BE.login.domain.SignUpDto;
import gdg.waffle.BE.login.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
@Slf4j
public class MemberServiceImpl implements MemberService {
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder; // 올바른 passwordEncoder 사용

    @Transactional
    @Override
    public JwtToken signIn(SignInDto signInDto) {
        String loginId = signInDto.getLoginId();
        String password = signInDto.getPassword();

        // ✅ ID 기반으로 회원 정보 조회
        Member member = memberRepository.findByLoginId(loginId)
                .orElseThrow(() -> new IllegalArgumentException("아이디가 일치하지 않습니다."));

        // ✅ 비밀번호 검증
        if (!passwordEncoder.matches(password, member.getPassword())) {
            log.error("비밀번호 불일치! 입력된 비밀번호: {}, 암호화된 비밀번호: {}", password, member.getPassword());
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }
        // 1. username + password 를 기반으로 Authentication 객체 생성
        // 이때 authentication 은 인증 여부를 확인하는 authenticated 값이 false
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginId, password);

        // 2. 실제 검증. authenticate() 메서드를 통해 요청된 Member 에 대한 검증 진행
        // authenticate 메서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드 실행
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        // 3. 인증 정보를 기반으로 JWT 토큰 생성
        return jwtTokenProvider.generateToken(authentication);

    }

    // 일반유저 회원가입
    @Transactional
    @Override
    public void signUp(SignUpDto signUpDto) {
        // 이메일 중복확인
        if (memberRepository.findByEmail(signUpDto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        // Password 암호화
        String encodedPassword = passwordEncoder.encode(signUpDto.getPassword());
        memberRepository.save(signUpDto.toEntity(encodedPassword));
    }

    // 아이디 중복 확인
    @Transactional
    @Override
    public void checkId(String loginId) {
        if (memberRepository.existsByLoginId(loginId)) {
            throw new IllegalArgumentException("이미 사용 중인 ID 입니다.");
        }
    }
}