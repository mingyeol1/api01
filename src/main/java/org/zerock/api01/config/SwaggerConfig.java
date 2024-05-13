package org.zerock.api01.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI(){

        // Security 스키마 설정

        SecurityScheme bearerAuth = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer") //bearer 타입 토큰이다.
                .bearerFormat("Authorization") // 인증 관련내용
                .in(SecurityScheme.In.HEADER)
                .name(HttpHeaders.AUTHORIZATION);

        //Security 요청 설정

        SecurityRequirement addSecurityItem = new SecurityRequirement();
        addSecurityItem.addList("Authorization");


        return new OpenAPI()
                .components(
                        new Components().addSecuritySchemes("Authorization", bearerAuth)
                )
                //API마다 Security 인증 컴포넌트 설정
                .addSecurityItem(addSecurityItem)
                .info(new Info().title("SpringDoc SwaggerUI Example")
                        .description("Test SwaggerUI application")
                        .version("v0.0.1"));
    }
}