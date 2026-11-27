package com.example.authserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * Step 2：授权服务器的核心配置。
 *
 * 这个类回答了 OAuth2 的几个关键问题：
 * 1. 用户是谁？        -> userDetailsService()（资源拥有者，写死一个账号）
 * 2. 哪些客户端允许来授权？ -> registeredClientRepository()（注册 client-app）
 * 3. token 怎么签发？  -> jwkSource()（RSA 私钥签 JWT，jwks 端点公布公钥供验签）
 * 4. 两套过滤链分工？  -> /oauth2/* 端点走"授权服务器链"，其余(如登录页)走"普通表单登录链"
 */
@Configuration
public class SecurityConfig {

    /** demo 用的密码编码器；{noop} 前缀表示明文存储，生产环境绝不允许 */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // ------------------------------------------------------------------
    // 过滤链 1：授权服务器自身的端点（/oauth2/authorize、/oauth2/token、
    // /oauth2/jwks、/oauth2/jwk-set 等）。框架根据"端点匹配器"识别这些请求。
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
    // 资源拥有者（登录用户）。真实项目这里查数据库，demo 写死一个。
    // 登录账号：user / password123
    // ------------------------------------------------------------------
    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}password123")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    // ------------------------------------------------------------------
    // 客户端注册：只有登记在案的第三方应用才能发起授权。
    // 这里的每一行都对应 OAuth2 协议里的一个概念。
    // ------------------------------------------------------------------
    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient clientApp = RegisteredClient.withId(UUID.randomUUID().toString())
                // client_id：客户端在授权服务器上的"身份证号"
                .clientId("client-app")
                // client_secret：机密客户端的身份凭证（confidential client）
                .clientSecret("{noop}client-secret")
                // 证明客户端身份的方式：HTTP Basic（/oauth2/token 请求头里带 Base64(client_id:client_secret)）
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 允许的授权方式：授权码 + 刷新令牌
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 授权完成后浏览器允许跳回的地址（必须一字不差，否则报 invalid_redirect_uri）
                .redirectUri("http://localhost:8000/login/oauth2/code/client-app")
                // 该客户端可申请的权限范围：读个人信息、读余额
                .scope("profile:read")
                .scope("balance:read")
                // 客户端级设置：是否要求用户"同意授权"页、是否强制 PKCE
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)   // 强制授权码 + PKCE
                        .build())
                // token 级设置：有效期、refresh token 是否轮换
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)  // 每次刷新都换新 refresh token（轮换）
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(clientApp);
    }

    // ------------------------------------------------------------------
    // 签发 access token 用的 RSA 密钥对。
    // access token 是 JWT：用私钥签名；资源服务器稍后用 /oauth2/jwks
    // 公布的公钥验签，这就是"token 防伪造"的原理。
    // demo 每次重启生成新密钥（旧 token 全部失效），生产环境应持久化密钥。
    // ------------------------------------------------------------------
    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA 算法不可用", e);
        }
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
