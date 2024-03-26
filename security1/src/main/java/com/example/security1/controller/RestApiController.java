package com.example.security1.controller;

import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.UserJwt;
import com.example.security1.repository.UserJwtRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


@Slf4j
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserJwtRepository userJwtRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token(){
        return "<h1>token</h1>";
    }


    @PostMapping("/join")
    public String join(@RequestBody UserJwt userJwt){
        userJwt.setPassword(bCryptPasswordEncoder.encode(userJwt.getPassword()));
        userJwt.setRoles("ROLE_USER");
        userJwtRepository.save(userJwt);
        return "회원가입완료";
    }

    // user,manager,admin  권한만 접근 가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication){
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        log.info("authentication");
        return "user";
    }

    // manager,admin 권한만 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }
    // admin 권한만 접근 가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
