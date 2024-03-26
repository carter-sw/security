package com.example.security1.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.UserJwt;
import com.example.security1.repository.UserJwtRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;


/*
Spring Security의 UsernamePasswordAuthenticationFilter 사용
        /login 요청해서 username, password를 POST로 전송하면
        UsernamePasswordAuthenticationFilter가 동작함
        but, formLogin().disable() 설정을 하면서 이 Filter가 동작을 하지 않음
        따라서 이 Filter를 SecurityConfig에 다시 등록을 해주어야 한다.
 */




@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private UserJwtRepository userJwtRepository;


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
 @Override
 public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
     System.out.println("로그인 시도: JwtAuthenticationFilter");

     // 1. username , pasword 받아서
     // 2. 정상인지 로그인 시도 authenticationManger로 로그인 시도를 하면
     // PrincipalDetailsService 가 호출 loadByUsername() 함수 실행됨.
     // 3 PrincipalDetails 를 세션에 담고 (권한 관리를 위해서)
     // 4.Jwt토큰을 만들어서 응답해주면 됨

     try {
//         BufferedReader br = request.getReader();
//
//         String input = null;
//         while ((input=br.readLine()) !=null){
//             System.out.println(input);
//         }
         ObjectMapper om = new ObjectMapper();
         UserJwt userJwt = om.readValue(request.getInputStream(),UserJwt.class);
         log.info(String.valueOf(userJwt));

         UsernamePasswordAuthenticationToken authenticationToken =
                 new UsernamePasswordAuthenticationToken(userJwt.getUsername(),userJwt.getPassword());

         // PrincipalDetailsService의 lodaUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴됨.
         // DB에 있는 username과 password가 일치한다
         Authentication authentication =
                 authenticationManager.authenticate(authenticationToken);


         PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
         log.info("로그인 완료됨: "+principalDetails.getUserJwt().getUsername()); // 로그인 정상적으로 되었다는 뜻

        // authentication 객체가 session 영역에 저장을 해야하고 그방법이 return 해주면됨
         // 리턴의 이유는 권한 관리를 security가 대신 해주기 떄문에 편하려고 하는거임.
         // 굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없음 근데 단지 권한 처리떄문에 session 넣어줌
         return authentication;

     } catch (IOException e) {
         throw new RuntimeException(e);
     }

 }
 //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // jwt 토큰을 만들어서 request요청한 사용자에게 jwt토큰을 response 해주면됨

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
     log.info("인증완료");
     PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();

        // RSA방식이 아닌, Hash암호방식
        String jwtToken = JWT.create()
                .withSubject("carter토큰")    // token 별명 느낌?
                .withExpiresAt(new Date(System.currentTimeMillis()+(JWTProperties.EXPIRATION_TIME)))  // (10분)Token 만료 시간 -> 현재시간 + 만료시간 (숫자로 넣으면 1/1000초)
                .withClaim("id", principalDetails.getUserJwt().getId())    // 비공개 Claim -> 넣고싶은거 아무거나 넣으면 됨
                .withClaim("username", principalDetails.getUserJwt().getUsername())    // 비공개 Claim
                .sign(Algorithm.HMAC512(JWTProperties.SECRET));  // HMAC512는 SECRET KEY를 필요로 함

        response.addHeader(JWTProperties.HEADER_STRING, JWTProperties.TOKEN_PREFIX+jwtToken);
        log.info("jwtToken: "+jwtToken);
    }
}
