package com.example.oauthjwt.jwt;

import com.example.oauthjwt.dto.CustomOAuth2User;
import com.example.oauthjwt.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// 각 요청마다 실행되어 JWT 토큰의 유효성 검사
// OncePerRequestFilter : 각 HTTP 요청마다 딱 한번만 실행되는 필터 구현

public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    // Spring Security 필터 체인에서 실행되는 메서드
    // 요청, 응다브 필터 체인을 매개변수로 받아 JWT 인증 처리 수행
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 모든 쿠키를 순회하면서 "Authorization" 이름의 쿠키를 찾는다 = 해당 쿠키가 JWT 토큰
        String authorization = null;
        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            System.out.println(cookie.getName());
            if(cookie.getName().equals("Authorization")) {
                authorization = cookie.getValue();
            }
        }

        if(authorization == null) {
            System.out.println("token is null");
            filterChain.doFilter(request, response); // 다음 필터로 요청을 전달
            return; // 메서드 종료 ( JWT 토큰 없으니깐 )
        }

        String token = authorization;    // 있으면 담아둔다

        // 만료되었는지 검사
        if(jwtUtil.isExpired(token)) {
            System.out.println("token is expired");
            filterChain.doFilter(request, response);
            return;
        }

        // 정보 추출 ( 유효한 토큰 )
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserDTO userDTO = new UserDTO();
        userDTO.setUsername(username);
        userDTO.setRole(role);

        // 인증된 사용자 담아
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        // Authentication : Spring Security의 인증 객체
        // 매개변수 ( 인증된 사용자 객체, 인증 자격 ( 인증되면 null) , 사용자 권한 목록 )
        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        // SecurityContextHolder : 현재 실행 중인 스레드의 보안 컨텍스트 정보를 저장하는 저장소
        // 현재 요청이 인증된 상태가 되며, 이후 보안 검사에서 이 인증 정보를 사용
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
