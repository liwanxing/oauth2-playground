package com.example.clientapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;

import com.example.clientapp.security.JwtClaimsUserService;

/**
 * Step 5：客户端安全配置——本步的灵魂是"补上 PKCE"。
 *
 * 背景坑：auth-server 的 ClientConfig 里配了 requireProofKey(true)（强制 PKCE），
 * 但 Spring 的机密客户端（配了 client_secret 的）默认发授权请求时【不带】PKCE 参数，
 * 直接点登录会被 auth-server 拒绝。下面用
 * DefaultOAuth2AuthorizationRequestResolver + OAuth2AuthorizationRequestCustomizers.withPkce()
 * 手工把 PKCE 加上：发起授权时生成随机 code_verifier，
 * 把它的 SHA-256（code_challenge）随授权请求发给 auth-server，
 * 稍后换 token 时再出示原始 code_verifier，auth-server 对哈希验证。
 *
 * 对应 GitHub 案例：PKCE 是"授权码防截获"的最后一道锁——
 * 即使授权码在重定向途中被人截走，没有 code_verifier 也换不到 token。
 *
 * oauth2Login：把「用 auth-server 登录」设为登录方式；
 * userInfoEndpoint.userService(...)：登录成功后"用户信息"从哪来，
 * 用我们自己写的 JwtClaimsUserService（见该类注释）。
 */
@Configuration
@EnableWebSecurity
public class ClientSecurityConfig {

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository) throws Exception {

        // 授权请求解析器：/oauth2/authorization/{registrationId} 是 Spring 客户端
        // 发起授权的固定入口（Step 4 冒烟时 302 跳转的目标路径）
        DefaultOAuth2AuthorizationRequestResolver resolver =
                new DefaultOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository, "/oauth2/authorization");
        // 关键一行：给授权请求加 PKCE（补上 Step 4 观察到的缺失参数 code_challenge）
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http
                .authorizeHttpRequests(authorize -> authorize
                        // 首页公开：没登录时显示"登录按钮"，登录后显示个人信息
                        .requestMatchers("/").permitAll()
                        // 其余（如 /logout）要求已登录
                        .anyRequest().authenticated())
                .oauth2Login(login -> login
                        // 用上面定制过的解析器发起授权（带 PKCE）
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver))
                        // 登录成功后如何获得"当前用户信息"（见 JwtClaimsUserService）
                        .userInfoEndpoint(userInfo -> userInfo.userService(new JwtClaimsUserService())))
                // 首页提供退出登录入口，退出后回到首页
                .logout(logout -> logout.logoutSuccessUrl("/"));

        return http.build();
    }
}
