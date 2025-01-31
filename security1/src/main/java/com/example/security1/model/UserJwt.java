package com.example.security1.model;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class UserJwt {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // autoincrement
    private long id;
    private String username;
    private String password;
    private String roles; //  USER , ADMIN

    public List<String> getRoleList(){
        if (this.roles.length() > 0){
            return Arrays.asList(this.roles.split(","));
        }
        return new ArrayList<>();
    }



}
