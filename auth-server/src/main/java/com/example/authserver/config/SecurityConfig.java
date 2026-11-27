package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * Step 2：授权服务器的"服务窗口"分流配置。
 *
 * 账号、客户端注册、RSA 密钥已拆到旁边的三个文件：
 * - UserConfig.java    账号数据库（登录认谁：user / password123）
 * - ClientConfig.java  合作网站名单（谁有资格发起授权：client-app）
 * - KeyConfig.java     公章（access token 的防伪签名）
 *
 * 本文件只回答一个问题：一个请求进来，该走哪条处理流程？
 * 1. /oauth2/* 端点（授权页、发 token、jwks）-> 授权服务器链
 * 2. /api/**  资源接口                       -> 资源服务器链（Step 3 加）
 * 3. 其余（登录页 /login）                   -> 表单登录链
 */
@Configuration
public class SecurityConfig {

    // ------------------------------------------------------------------
    // 过滤链 1：授权服务器自身的端点（/oauth2/authorize、/oauth2/token、
    // /oauth2/jwks 等）。框架根据"端点匹配器"识别这些请求。
    // ------------------------------------------------------------------
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // 只让这条链处理"授权服务器端点"的请求
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // 未登录时访问授权端点（如 /oauth2/authorize），
                // 若浏览器请求(HTML)则重定向到 /login 登录页，而不是返回 401 JSON
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        return http.build();
    }

    // ------------------------------------------------------------------
    // 过滤链 2：其余所有请求（目前就是登录页 /login 本身）。
    // Step 3 会在这两条链之间再插入一条"资源服务器链"保护 /api/**。
    // ------------------------------------------------------------------
    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // Spring Security 自带的默认登录页，体验时不用自己写 HTML
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    // ------------------------------------------------------------------
    // 授权服务器元数据：issuer 等基础信息。
    // 启动后访问 http://localhost:9000/oauth2/authorization-server 可看到这份元数据。
    // ------------------------------------------------------------------
    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }
}
