package org.zerock.api01.util;



import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    @Value("${org.zerock.jwt.secret}")   //application.properties 설정된 값을 불러오는 어노테이션
    public String key;

    //토큰 생성 메서드
    public String generateToken(Map<String, Object> valueMap, int days){
        log.info("generatekey...."+ key);

        //헤더 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", "HS256");  //256은 길이 값

        // payload 부분
        Map<String, Object> payload = new HashMap<>();
        payload.putAll(valueMap); //넘겨온 벨류 값을 여기로 다 받는다.

        // 토큰 생성 시간 설정...
        int time = (60 * 24) * days;

        String jwtStr = Jwts.builder()
                .setHeader(headers)
                .setClaims(payload)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                .signWith(SignatureAlgorithm.HS256, key.getBytes())
                .compact();


    return jwtStr;
    }

    // 토큰 검증 메서드...
    public Map<String,Object> validateToken(String token) throws JwtException {
        Map<String,Object> claim = null;

        claim = Jwts.parser()
                .setSigningKey(key.getBytes()).build()
                .parseSignedClaims(token) // Set key
                .getBody();

        return claim;
    }

}
