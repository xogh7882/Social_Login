package com.example.oauthjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    // JWT 토큰을 생성하고 검증할 때 사용하는 암호화 키  -> 토큰 서명 및 검증에 사용
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret){
        // getByte(StandardCharsets.UTF_8) : UTF-8 인코딩으로 바이트 배열로 변환
        // Jwts.SIG.HS256.key().build().getAlgorithm() : HS256 이라는 알고리즘을 가져와서 사용 ( 대칭키 알고리즘 )
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token){
        // Jwt.parser() : JWT 파서
        // verifyWith(secretKey) : 토큰 검증에 사용할 비밀 키 지정
        // build() : 설정된 옵션으로 JWT 파서 구성
        // parseSignedClaims(token) : 전달된 JWT 토큰 문자열 파싱  ->  토큰 서명 검증 ( 서명 유효X = 예외 발생 )
        // getPayload() : 검증된 토큰에서 페이로드를 가져온다
        // get("username", String.class) : 페이로드에서 "username" 키를 가진 클레임 값을 String 타입으로 추출

        // Payload : JWT = ( Header(토큰유형 및 알고리즘) + Payload(실제 데이터) + Signature(무결성 검증) )
        // 1. 클레임 포함 : 사용자나 추가 데이터에 대한 설명을 담은 이름-값 쌍
        // 2. 등록된 클레임 : 만료시간, 발생시간,   +   사용자 정의 클레임 : username, email 등
        // 3. JSON 형식
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String CreateJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }

}
