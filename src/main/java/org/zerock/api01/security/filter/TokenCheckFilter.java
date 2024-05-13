package org.zerock.api01.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.exception.AccessTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI(); //경로 받아오기
        if(!path.startsWith("/api/")){ // 경로가 /api/로 접근한게 아니라면
            filterChain.doFilter(request, response);//다음 필터로 넘어간다.
            return;
        }

        log.info("Token Check Filter.......................");
        log.info("JWTUtile : "+jwtUtil);

        try {
            validateAccessToken(request);
            filterChain.doFilter(request, response);
        }catch (AccessTokenException accessTokenException){
            accessTokenException.sendResponseError(response);
        }


      //  filterChain.doFilter(request,response);//다음 필터로 넘어간다.

    }

    private Map<String , Object> validateAccessToken(HttpServletRequest request) throws AccessTokenException {
        String headerStr = request.getHeader("Authorization"); //Authorization라는 헤더에 타입과 벨류값이 들어있음. //토큰이 저장될 헤더
        if (headerStr == null || headerStr.length() < 8){ //토큰이 없는 경우..
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
        }
        // Bearer 생략
        String tokenType = headerStr.substring(0,6);
        String tokenStr = headerStr.substring(7);

        if(tokenType.equalsIgnoreCase("Bearer") == false){ //잘못된 타입.
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADTYPE);
        }

        try{
            Map<String, Object> values = jwtUtil.validateToken(tokenStr);
            return values;
        }catch (MalformedJwtException malformedJwtException){
            log.info("MalformedJwtException-------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
        }catch (SignatureException signatureException){
            log.info("SignatureException---------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
        }catch (ExpiredJwtException expiredJwtException){
            log.info("ExpiredJwtException-----------------------------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
        }

    }

}
