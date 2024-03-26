package com.example.security1.repository;


import com.example.security1.model.User;
import com.example.security1.model.UserJwt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


// CRUD 함수를 JpaRepository가 들고있음
// @Repository 라는 어노테이션이 없어도 Ioc가 됨, 이유는 JpaRepository를 상속했기 떄문
@Repository
public interface UserJwtRepository extends JpaRepository<UserJwt,Integer> {

    // findByUsername 메서드의 반환 타입을 UserJwt로 변경
    UserJwt findByUsername(String username);


}
