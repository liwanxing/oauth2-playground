package com.example.authserver.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 3：个人信息接口。
 *
 * 对应授权流程里的 scope：profile:read。
 * client-app 拿着 access token 来调这个接口时，token 已经被资源服务器
 * 过滤链（ResourceServerConfig）验过签了——能进到方法里，说明 token 是真的。
 *
 * @AuthenticationPrincipal Jwt jwt：框架把验签后的 token 内容直接注入这个参数。
 * token 是个三段式的 JWT，中间一段（payload）就是一串声明（claims），
 * 这里挑几个有意思的展示出来，让你直观看到"token 里到底装了什么"。
 */
@RestController
public class MeController {

    @GetMapping("/api/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        // scope 声明：这张通行证被允许的权限列表（发 token 时按你勾选的授权生成）
        List<String> scopes = jwt.getClaimAsStringList("scope");

        Map<String, Object> result = new HashMap<>();
        // sub（subject）：token 主人 = 登录时用的用户名，这里就是 "user"
        result.put("sub", jwt.getSubject());
        result.put("scopes", scopes == null ? List.of() : scopes);
        // exp（expiration）：过期时间戳。注意 Step 2 里配了 access token 只有 5 分钟有效
        result.put("expiresAt", jwt.getExpiresAt() == null ? null : jwt.getExpiresAt().toString());
        // iss（issuer）：签发机构，就是 SecurityConfig 里配的 issuer 地址
        result.put("issuer", jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
        return result;
    }
}
