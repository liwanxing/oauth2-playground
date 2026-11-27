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
 * 整个 OAuth2 流程分三个阶段：
 *   阶段一：登录       —— 你证明"你是你"（输 user/password123）
 *   阶段二：授权+发证  —— 你同意 client-app 代表你，然后发一张通行证（token）
 *   阶段三：凭证办事   —— client-app 拿通行证来调接口（/api/balance 等）
 *
 * 三条过滤链的分工（按网址分流，不是"正常登录 vs 授权登录"）：
 *   1. /oauth2/* 端点（阶段二：同意授权、发 token、jwks）  -> 授权服务器链（本文件 @Order(1)）
 *   2. /api/**   资源接口（阶段三：验 token、给数据）      -> 资源服务器链（ResourceServerConfig.java @Order(2)）
 *   3. 其余（登录页 /login 本身，阶段一登录动作发生地）    -> 表单登录链（本文件 @Order(3)）
 *
 * 注意：阶段一（登录）的页面和动作发生在链 3，但它是被链 1 的授权流程
 * 带出来的（未登录访问授权端点 -> 重定向到 /login -> 登录后跳回）。
 * 链 3 和授权流程没有必然关系——你自己直接开浏览器访问
 * http://localhost:9000/login 也能登录，这是"网站自己能登录"的普通能力；
 * 授权流程（阶段一）只是借用这个登录页而已。
 */
@Configuration
public class SecurityConfig {

    // ------------------------------------------------------------------
    // 过滤链 1：授权服务器自身的端点（阶段二：同意授权、发 token 都在这里发生）。
    // /oauth2/authorize 授权页、/oauth2/token 发 token、/oauth2/jwks 公布公钥。
    //
    // 和阶段一（登录）的关系：登录页面本身在链 3（见下面），但登录是
    // 被本链带出来的——未登录访问 /oauth2/authorize 时，下面的
    // exceptionHandling 会把浏览器重定向到 /login 去登录，
    // 登录成功后浏览器回到 /oauth2/authorize，本链继续走同意页、发 token。
    //
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
    // 过滤链 3：其余所有请求（目前就是登录页 /login 本身）。
    // 它接待的是浏览器、管的是"网站自己能登录"这件事；
    // 阶段一的登录动作（展示登录页、接收账号密码、建立会话）就发生在这里。
    // 注意：本链自己不知道 OAuth2 的存在——授权流程只是"借用"这个登录页，
    // 登录完把浏览器送回链 1 的授权端点继续办业务。
    // 阶段三（client-app 拿 token 来调 /api/**）已由 ResourceServerConfig
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
