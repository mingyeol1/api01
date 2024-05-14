package org.zerock.api01.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.filter.RefreshTokenFilter;
import org.zerock.api01.security.filter.TokenCheckFilter;
import org.zerock.api01.security.handler.APILonginSuccessHandler;
import org.zerock.api01.util.JWTUtil;

import java.util.Arrays;

@Configuration
@Log4j2
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    //의존성 주입 - 실제 인증처리를 위한 AuthenticationManager 객체 설정이 필요하다.
    private final APIUserDetailsService apiUserDetailsService;

    private final JWTUtil jwtUtil;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("------------------------------- web configure---------------------");

        //정적 리소스 필터링 제외  시큐리티에서
        return (web) -> web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );

    }

    @Bean
    public SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
        log.info("---------------------------------- configure configure---------------------");

       // AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                        .passwordEncoder(passwordEncoder());
//-----------------------------------------------------------

        // Get AuthenticationManager //인증 매니저 등록
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build(); //구현체

        //인증 매니저 등록
        http.authenticationManager(authenticationManager);

        //APILoginFilter 설정.....!
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        //APILoginFilter의 위치 조정 - UsernamePasswordAuthenticationFilter 이전에 동작해야 하는 필터 이기 때문에 먼저 동작.
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // APILoginSuccessHandler
        APILonginSuccessHandler successHandler = new APILonginSuccessHandler(jwtUtil);
        //SuccessHandler 설정
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        //api로 시작하는 모든 경로는 TokenCheckFilter 동작 시킨다.
        http.addFilterBefore(
                tokenCheckFilter(jwtUtil),
                UsernamePasswordAuthenticationFilter.class
        );

        // refreshToken 호출 처리..  //경로가 /refreshToken 인 경우에만 접근 처리를 하겠다.
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil),
                TokenCheckFilter.class);



        // 1. CSRF 토큰의 비활성화
        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        // 2. 세션 사용을 않는다. REST 형식으로 만들어서.
        http.sessionManagement(httpSecuritySessionManagementConfigurer ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                ));

        //CORS 설정 CORS 필터 설정 적용
        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());
        });

        return http.build();
    }

    // CORS 필터 빈(Bean). 설정 소스.

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        //접근할 URL을 지정하여 처리한다. "*" 는 모든 주소의 접근을 허용. 대상 지정하면 지정 대상만 접근 가능하다."http:/localhost:8090"
        corsConfiguration.setAllowedOriginPatterns(Arrays.asList("*")); //"*"들어오는 거 전부.
        corsConfiguration.setAllowedMethods(Arrays.asList("HEAD","GET", "POST", "PUT", "DELETE")); //허용하고 있는 메서드
        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization","Cache-Control" ,"Content-Type"));
        corsConfiguration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration); // "/**" 하위 모든 폴더 모든 경로를 다 포함하겠다.
        return source;
    }


    //토큰 체크 필터 객체 생성
    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil) {
        return new TokenCheckFilter(jwtUtil);
    }



}
