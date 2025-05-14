package com.example.oauthjwt.config;

import com.example.oauthjwt.jwt.JWTFilter;
import com.example.oauthjwt.jwt.JWTUtil;
import com.example.oauthjwt.oauth2.CustomSuccessHandler;
import com.example.oauthjwt.service.CustomOAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity  // Spring Security 기능 활성화
public class SecurityConfig {
        // OAuth2로 가져온 사용자 정보를 처리하는 서비스
        private final CustomOAuth2UserService customOAuth2UserService;
        // OAuth2 로그인 성공 시 JWT 생성 및 쿠키 설정을 담당
        private final CustomSuccessHandler customSuccessHandler;
        // JWT 관련 유틸리티 클래스
        private final JWTUtil jwtUtil;

        public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler, JWTUtil jwtUtil) {
                this.customOAuth2UserService = customOAuth2UserService;
                this.customSuccessHandler = customSuccessHandler;
                this.jwtUtil = jwtUtil;
        }

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                        .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                                @Override
                                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                                        CorsConfiguration configuration = new CorsConfiguration();

                                        //매개변수로 오는 요청만 허용
                                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:5173"));
                                        // 모든 HTTP 메서드 허용 ( GET, POST, PUT, DELETE )
                                        configuration.setAllowedMethods(Collections.singletonList("*"));
                                        // 쿠키와 같은 인증 정보를 포함한 요청 허용
                                        configuration.setAllowCredentials(true);
                                        // 모든 헤더 타입 허용
                                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                                        // 요청응답을 3600초 동안 캐싱
                                        configuration.setMaxAge(3600L);

                                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                                        return configuration;
                                }
                        }));

                //csrf disable ( CSRF 보호 비활성화 )
                http.csrf((auth) -> auth.disable());

                //Form 로그인 방식 disable ( 기본 제공 폼 로그인 방식 비활성화 )
                http.formLogin((auth) -> auth.disable());

                //HTTP Basic 인증 방식 disable ( HTTP Basic 인증 방식 비활성화 )
                http.httpBasic((auth) -> auth.disable());


                // JWT Filter 추가
                // UsernamePasswordAuthenticationFilter : 사용자 이름, 비밀번호 기반의 로그인 인증 처리 필터
                http.addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

                //oauth2
                // userInfoEndpoint : 사용자 정보 조회
                // deaultSuccessUrl : 로그인 성공 시, 넘어가는 페이지 설정

                http
                        .oauth2Login((oauth2) -> oauth2
                                .userInfoEndpoint((userInfoEndpointConfig -> userInfoEndpointConfig
                                        .userService(customOAuth2UserService)))
                                .successHandler(customSuccessHandler)
                        );

                //경로별 인가 작업
                http
                        .authorizeHttpRequests((auth) -> auth
                                .requestMatchers("/").permitAll()   // "/" 경로는 모든 사용자가 접근 가능
                                .requestMatchers("/api/auth/logout").permitAll()
                                .anyRequest().authenticated());       // 나머지는 인증된 사용자만 접근 가능



                //세션 설정 : STATELESS ( JWT는 세선 사용 X )
                http
                        .sessionManagement((session) -> session
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));


                return http.build();
        }

}
