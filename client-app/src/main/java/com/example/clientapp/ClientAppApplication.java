package com.example.clientapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Step 4：第三方客户端应用的启动类。
 *
 * 对应「用 GitHub 登录」案例：本应用扮演那个在自己网站上挂
 * 「用 auth-server 登录」按钮的第三方网站。
 * 它跑在 8000 端口，和授权服务器（9000）是两个独立的应用。
 */
@SpringBootApplication
public class ClientAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientAppApplication.class, args);
    }
}
