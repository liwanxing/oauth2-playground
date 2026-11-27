package com.example.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 授权服务器入口。
 *
 * 现在还只是个空壳：启动后除了 Spring Boot 自带的错误页，什么都没有。
 * Step 2 会加上 SecurityConfig，让它具备"发授权码、发 token"的能力。
 */
@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
