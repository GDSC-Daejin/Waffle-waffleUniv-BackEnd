package gdg.waffle.BE.login.service;

import gdg.waffle.BE.common.jwt.JwtToken;

public interface MemberService {
    /**
     * 사용자의 아이디와 비밀번호로 로그인을 처리하고 JWT 토큰을 반환.
     * @param username 사용자 이름
     * @param password 비밀번호
     * @return 생성된 JWT 토큰
     */
    public JwtToken signIn(String username, String password);}
