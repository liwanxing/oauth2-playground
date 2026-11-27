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
 * 对应「用微信登录」比喻里的"微信的账号数据库"。
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
     * 这就是授权流程里「资源拥有者」（Resource Owner）——能点头同意的那个用户。
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
