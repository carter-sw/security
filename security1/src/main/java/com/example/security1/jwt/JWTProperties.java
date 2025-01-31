package com.example.security1.jwt;

public interface JWTProperties {
    String SECRET = "carter";   // 우리 서버만 알고 있는 비밀 값
    int EXPIRATION_TIME = 60000*10*5; // Token 만료(10분 설정*5)
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
