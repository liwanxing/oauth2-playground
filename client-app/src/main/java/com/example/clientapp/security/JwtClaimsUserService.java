package com.example.clientapp.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * 登录成功后的"用户信息提供者"。
 *
 * 为什么不用框架默认的？Spring 默认逻辑是"拿着 access token 去调
 * 授权服务器的用户信息端点（/userinfo）"——那要求额外配置 userinfo 能力。
 * 而我们的 access token 本身就是一张 JWT（三段式），中间一段就是
 * 用户相关的声明（claims），客户端本地解开就能用，无需再发一次请求。
 *
 * 注意安全边界：这里解出来的内容只用于【展示】（欢迎语、查看 token 里有什么），
 * 不用于任何权限判断——因为 JWT 内容未经客户端验签，理论上可被篡改。
 * 真正的权限控制都在 auth-server 侧（验签 + scope 检查）。
 */
public class JwtClaimsUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // access token 是三段式 JWT：header.payload.signature（各自 base64url 编码）
        String tokenValue = userRequest.getAccessToken().getTokenValue();
        try {
            // 取中间一段（payload），解开就是一串 claims：sub、scope、exp、iss...
            String[] parts = tokenValue.split("\\.");
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> claims =
                    objectMapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});

            // 把 token 里的 scope 转成权限标记（SCOPE_xxx），与其他地方的习惯保持一致
            List<GrantedAuthority> authorities = userRequest.getAccessToken().getScopes().stream()
                    .map(scope -> (GrantedAuthority) new SimpleGrantedAuthority("SCOPE_" + scope))
                    .toList();

            // "sub" 指定用 claims 里的哪个字段当用户名
            return new DefaultOAuth2User(authorities, claims, "sub");
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_token", "解析 access token 声明失败", null), e);
        }
    }
}
