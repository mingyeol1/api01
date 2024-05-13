package org.zerock.api01.security.handler;

import com.google.gson.Gson;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.util.Map;


@Log4j2
@RequiredArgsConstructor
public class APILonginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtil jwtUtil; //토큰 발행을 위한 의존성 주입


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("Login success Handler----------------------------------------");

    //----- 토큰발행
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        log.info(authentication); //인증정보가 들어있음
        log.info(authentication.getName()); // username

        Map<String, Object> claim = Map.of("mid",authentication.getName());
        //Access Token 유효기간 1일
        String accessToken = jwtUtil.generateToken(claim,1);
        //Refresh Token 유효기간 30일
        String refreshToken = jwtUtil.generateToken(claim,30);

        Gson gson = new Gson();
        Map<String, String> keyMap = Map.of( //제이슨 파일은 객체가 아니라 문자열이라 String
                "accessToken",accessToken,
                "refreshToken", refreshToken
        );

        String jsonStr = gson.toJson(keyMap);
        response.getWriter().println(jsonStr);
    }
}
