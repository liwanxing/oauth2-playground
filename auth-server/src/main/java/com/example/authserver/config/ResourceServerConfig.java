package com.example.authserver.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Step 3：资源服务器配置——第三步（凭证办事）的验票窗口。
 *
 * 对应 GitHub 案例：你拿 GitHub 发的 token 去调 GitHub API（api.github.com）
 * 时，GitHub 后端会先验证 token 真伪，再看 token 里有没有对应的权限。
 * GitHub 的 API 就是"资源服务器"，本文件给我们的 /api/** 装上同样的能力：
 *
 * 1. jwtDecoder()：验签工具。client-app 请求头里带的 access token 是一张
 *    盖了章的 JWT（KeyConfig 里那枚 RSA 私钥签的名），这里用公布的公钥验证
 *    签名，伪造的 token 验签不过，直接被拒。
 * 2. 资源服务器过滤链：凡是 /api/** 的请求，先验 token，没带 token 返回 401。
 *
 * 注意：资源服务器不重新发 token，它只"消费"token——这就是 JWT 的好处：
 * 验证在自己本地完成，不需要每次都去问授权服务器。
 *
 * @EnableMethodSecurity：开启方法级权限检查，让 Controller 里能写 @PreAuthorize
 * 注解（BalanceController 用它做"查权限"，scope 不够返回 403）。
 */
@Configuration
@EnableMethodSecurity
public class ResourceServerConfig {

    /**
     * 验签工具：基于 KeyConfig 里的公钥（jwkSource）构建。
     * 资源服务器链会自动发现这个 Bean 并用它验证每个 /api/** 请求的 token。
     */
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // ------------------------------------------------------------------
    // 过滤链 2：资源接口 /api/**（第三步）。
    // 排在授权服务器链（@Order(1)）之后、表单登录链（@Order(3)）之前。
    // ------------------------------------------------------------------
    @Bean
    @Order(2)
    SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 这条链只管 /api/** 开头的请求
                .securityMatcher("/api/**")
                // 所有接口都要求"已验证的 token"：没带 token 或验签失败 -> 401
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // 启用"资源服务器"模式，用 JWT 方式验 token（自动使用上面的 jwtDecoder Bean）。
                // 这一行就是把 token 从请求头里抽出来、验签、解析出"是谁+有什么权限"的全过程。
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
