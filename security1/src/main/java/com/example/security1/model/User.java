package com.example.security1.model;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

@Data
@NoArgsConstructor
@Entity
public class User {
    @Id //primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role; // ROLE_USER,ROLE_ADMIN

    private String provider; // google
    private String prividerId; // google에서 받은 번호

    @CreationTimestamp
    private Timestamp createDate;

    @Builder
    public User(String username, String password, String email, String role, String provider, String prividerId, Timestamp createDate) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.prividerId = prividerId;
        this.createDate = createDate;
    }
}
