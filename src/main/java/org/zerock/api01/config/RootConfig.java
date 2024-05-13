package org.zerock.api01.config;

import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/* modelMapper 설정 */
@Configuration //Component 등록되어 있는 녀석들은 어플리케이션 컨텍스트로 들어감.
@EnableJpaAuditing
public class RootConfig {
    //스프링 설정을 코드로 하는것
    @Bean
    public ModelMapper getMapper(){
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration()
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE)
                .setMatchingStrategy(MatchingStrategies.LOOSE); //LOOSE 딱딱하게 하지 않는다 ?
        return modelMapper; //특징 dto 와 vo를 변환을 해준다. STRICT : 이름이 똑같아야 바뀜 / 변수명과 데이터 타입이 같아야함.
    }


}
