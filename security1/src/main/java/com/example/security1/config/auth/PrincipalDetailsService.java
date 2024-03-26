package com.example.security1.config.auth;

import com.example.security1.model.User;
import com.example.security1.model.UserJwt;
import com.example.security1.repository.UserJwtRepository;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessingUrl ("/login"); (login, 소셜로그인)설명
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 loc 되어있는 loadUserByUsername 함수가 실행


// http://localhost:8080/login jwt 설명 => 여기서 동작을 안한다
@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserJwtRepository userJwtRepository;

    // 시큐리티 session(내부 Authentication(내부 UserDetails))
    // @AuthenticationPrincipal 어노테이션이 만들어진다 (login, 소셜로그인 사용)
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        System.out.println("username:"+username);
//        User userEntity = userRepository.findByUsername(username);
//        if(userEntity != null){
//            return new PrincipalDetails(userEntity);
//        }
//        return null;
//    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService의 loadUserByUsername()");
        UserJwt userJwtEntity = userJwtRepository.findByUsername(username);
        return new PrincipalDetails(userJwtEntity);
    }
}
