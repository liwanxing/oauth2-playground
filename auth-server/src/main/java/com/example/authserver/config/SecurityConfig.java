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
 *
 * 整个授权流程分三步（站在 client-app 视角）：
 *   第一步：发起授权 —— client-app 把你的浏览器带到授权服务器（Step 4 的 client-app 触发）
 *   第二步：登录 + 同意 + 发证 —— 在授权服务器完成：
 *           你输账号密码（登录页）、点"同意授权"（同意页）、拿到一张通行证（token）
 *   第三步：凭证办事 —— client-app 拿通行证来调接口（/api/balance 等）
 *
 * 三条过滤链的分工（按网址分流）：
 *   1. /oauth2/* 端点（第二步里的"同意授权、发 token"）  -> 授权服务器链（本文件 @Order(1)）
 *   2. /api/**   资源接口（第三步：验 token、给数据）     -> 资源服务器链（ResourceServerConfig.java @Order(2)）
 *   3. /login    登录页（第二步里的"登录"这步的页面）     -> 表单登录链（本文件 @Order(3)）
 *
 * 第二步跨了链 1 和链 3：未登录访问授权端点时，链 1 会把浏览器重定向
 * 到链 3 的登录页；登录成功后浏览器跳回链 1 继续走同意页、发 token。
 */
@Configuration
public class SecurityConfig {

    // ------------------------------------------------------------------
    // 过滤链 1：授权服务器自身的端点（第二步里的"同意授权、发 token"在这里发生）。
    // /oauth2/authorize 授权页、/oauth2/token 发 token、/oauth2/jwks 公布公钥。
    // 未登录访问时，下面的 exceptionHandling 会把浏览器重定向到
    // /login（链 3 的登录页），登录成功后跳回这里继续走流程。
    // 框架根据"端点匹配器"识别这些请求。
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
    // 过滤链 3：登录页 /login（第二步里"登录"这步的页面在这里）。
    // 展示登录页、接收账号密码、建立登录会话。
    // 登录成功后，浏览器被送回链 1 的授权端点继续走同意页、发 token。
    // 第三步（client-app 拿 token 调 /api/**）由 ResourceServerConfig
    // 的资源服务器链（@Order(2)）接管，不会落到本链。
    // ------------------------------------------------------------------
    @Bean
    @Order(3)
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
