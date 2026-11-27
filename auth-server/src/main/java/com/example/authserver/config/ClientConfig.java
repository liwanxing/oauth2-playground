package com.example.authserver.config;

import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

/**
 * 客户端注册：合作网站名单。
 *
 * 对应「用微信登录」比喻里的"签约登记表"——
 * 不是谁都能在自家网站挂「用微信登录」按钮，得先来这里登记。
 * 每一行都对应 OAuth2 协议里的一个概念。
 */
@Configuration
public class ClientConfig {

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
}
