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
 * 客户端注册：对应 GitHub 的「OAuth App 注册」。
 *
 * 真实世界里，第三方网站想提供「用 GitHub 登录」，开发者要先去 GitHub 的
 * Settings → Developer settings → OAuth Apps 页面登记应用：填应用名、
 * 回调地址，登记后拿到 client_id / client_secret。
 * 本文件干的就是这件事——给我们的 client-app 在授权服务器上做同样的登记。
 * 每一行都对应 OAuth2 协议里的一个概念。
 */
@Configuration
public class ClientConfig {

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient clientApp = RegisteredClient.withId(UUID.randomUUID().toString())
                // client_id：应用在授权服务器上的身份标识（GitHub 登记后会发一个
                // 形如 Iv1.xxxx 的串），相当于应用的"身份证号"，可以公开
                .clientId("client-app")
                // client_secret：相当于应用的"密码"（机密客户端 confidential client），
                // 只存在服务器后台，绝不能出现在网页或手机 App 里
                .clientSecret("{noop}client-secret")
                // 换 token 时怎么证明"我是登记过的应用"：HTTP Basic，
                // 即 /oauth2/token 请求头里带 Base64(client_id:client_secret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 允许的授权方式：授权码（第一次拿 token 的主流程）+ refresh token（续期用）
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 对应 GitHub 注册页里填的 "Authorization callback URL"：
                // 授权完成后浏览器允许跳回的地址（必须一字不差，否则报
                // invalid_redirect_uri——这是防止授权码被发到攻击者网站的安全设计）
                .redirectUri("http://localhost:8000/login/oauth2/code/client-app")
                // 对应 GitHub 授权页上的勾选项（read:user、repo 那些）：
                // 该客户端允许申请的权限范围只有这两项，申请范围外的权限会被拒绝。
                // token 能干什么 = 用户同意了这里的哪些项
                .scope("profile:read")
                .scope("balance:read")
                // requireAuthorizationConsent：强制弹出 GitHub 那种
                // "该应用想要以下权限，是否同意" 的确认页
                // requireProofKey：强制 PKCE，给授权码再加一道防截获锁（Step 5 细讲）
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                // token 级设置：access token 5 分钟过期（过期后靠 refresh token 续期）、
                // refresh token 8 小时；reuseRefreshTokens(false) 表示每次刷新都换新
                // refresh token（轮换）——旧的一张作废，捡到也来不及用
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(clientApp);
    }
}
