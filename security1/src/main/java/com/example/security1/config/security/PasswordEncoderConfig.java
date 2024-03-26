package com.example.security1.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordEncoderConfig {
    @Bean
    public PasswordEncoder passwordEncoder(){
        // BCryptPasswordEncoder 인스턴스를 생성하여 리턴
        // 이 인스턴스는 Spring Security에서 비밀번호를 인코딩(암호화)하거나
        // 제출된 비밀번호가 저장된 비밀번호와 일치하는지 확인하는 데 사용됨

        // 해당 메서드의 리턴되는 오브젝트를 loc로 등록해준다.
        return new BCryptPasswordEncoder();
    }
}
