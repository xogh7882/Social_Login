package com.example.oauthjwt.oauth2;

import com.example.oauthjwt.dto.CustomOAuth2User;
import com.example.oauthjwt.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
// SimpleUrlAuthenticationSuccessHandler : 인증 성공 핸들러 클래스
// 인증 성공 후 사용자를 특정 URL로 Redirect 하는 기능 제공
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JWTUtil jwtUtil;

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    //소셜 로그인 인증 성공 시 호풀되는 메서드
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // getPrincipal : 인증된 사용자 객체를 가져온다.
        // 이를 CustomAuth2User 타입으로 형변환
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        // 인증된 사용자명 추출
        String username = customOAuth2User.getUsername();

        // 인증 객체에서 사용자의 권한 목록을 가져온다
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        System.out.println("authorities : " + authorities);

        // 권한 컬렉션에 접근하기 위한 반복자 생성
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();

        // 첫번째 권한 객체를 가져온다
        GrantedAuthority auth = iterator.next();

        // 권한 객체에서 권한 문자열을 추출
        String role = auth.getAuthority();

        // 사용자명, 역할, 유효기간을 포함한 JWT 토큰 생성
        String token = jwtUtil.CreateJwt(username,role,60*60*60L);

        // 생성된 JWT 토큰을 "Authorization" 이름의 쿠키에 저장
        response.addCookie(createCookie("Authorization", token));

        // 쿠키 설정 후 사용자를 프런트로 Redirect
        response.sendRedirect("http://localhost:5173/");
    }

    private Cookie createCookie(String key, String value){

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60*60*60);
        cookie.setPath("/");
//        cookie.setHttpOnly(true);
        return cookie;
    }
}
