package com.example.oauthjwt.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        // 애플리케이션의 모든 경로에 CORS 설정 적용
        corsRegistry.addMapping("/**")
                // 서버에서 클라이언트로 보내는 응답에서 "Set-Cookie" 헤더를 노출
                .exposedHeaders("Set-Cookie")
                // 매개변수로 오는 요청만 허용
                .allowedOrigins("http://localhost:5173");
    }
}