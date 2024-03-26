package com.example.security1.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.security1.config.auth.PrincipalDetails;
import com.example.security1.model.UserJwt;
import com.example.security1.repository.UserJwtRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// 시큐리티가 filter 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청 했을떄 위 필터를 무조건 타게 되어있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탐.
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserJwtRepository userJwtRepository;


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserJwtRepository userJwtRepository) {

        super(authenticationManager);
        this.userJwtRepository = userJwtRepository;

    }

    // 인증이나 권한이 필요한 주소요청이 있을떄 해당 필터를 타게 됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증이나 권한이 필요한 주소 요청이 됨.");

        String jwtHeader = request.getHeader(JWTProperties.HEADER_STRING);
        log.info("jwtHeader: "+jwtHeader);

       // jwt 토큰이나 Bearer가 아니면 (header가 있는지 확인)
        if(jwtHeader == null|| !jwtHeader.startsWith(JWTProperties.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }
        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        String jwtToken = request.getHeader(JWTProperties.HEADER_STRING).replace(JWTProperties.TOKEN_PREFIX,"");

        String username                                                            //principalDetails.getUserJwt().getUsername()
                = JWT.require(Algorithm.HMAC512(JWTProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적으로 됨
        if(username != null) {

            UserJwt userjwtEntity = userJwtRepository.findByUsername(username);


            PrincipalDetails principalDetails = new PrincipalDetails(userjwtEntity);

            // JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null,principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }
        chain.doFilter(request,response);
    }
}
