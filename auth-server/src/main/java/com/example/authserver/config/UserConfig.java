package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * 账号配置：登录页上输的账号密码认谁。
 *
 * 对应 GitHub 案例：点「用 GitHub 登录」后跳到 github.com 的登录页，
 * 你在那里输的是你的 GitHub 账号密码——先证明"你是这个账号的主人"。
 * 本文件里的 user / password123 扮演的就是这个 GitHub 账号。
 * 真实项目这里查数据库，demo 写死一个账号。
 */
@Configuration
public class UserConfig {

    /** demo 用的密码编码器；{noop} 前缀表示明文存储，生产环境绝不允许 */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 登录账号：user / password123
     * 这就是授权流程里「资源拥有者」（Resource Owner）——能点头同意授权的那个用户。
     */
    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}password123")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}
