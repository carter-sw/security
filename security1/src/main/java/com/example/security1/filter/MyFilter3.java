package com.example.security1.filter;


import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰 : cos 이걸 만들어줘야함. id,pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할때마다 header에 Authorization에 value값으로 토큰을 가지고옴
        // 그떄 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면됨. (RSA,HS256)

        if(req.getMethod().equals("POST")){
            log.info("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            log.info(headerAuth);
            log.info("필터3");

            if(headerAuth != null && headerAuth.equals("cos")){ // null 체크 추가
                chain.doFilter(request,response);
            }  else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
