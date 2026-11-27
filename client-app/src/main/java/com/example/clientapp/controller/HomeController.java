package com.example.clientapp.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

/**
 * Step 5：客户端首页 —— 完整流程的"剧场"。
 *
 * 没登录时：显示「用 auth-server 登录」按钮（点它就走完整授权流程）。
 * 登录后：显示个人信息（调 /api/me）和余额（调 /api/balance）。
 *
 * 重点看 callApi()：这就是"后端代理调资源服务器"——
 * token 只存在于 client-app 的服务器端（会话里），浏览器全程摸不到；
 * 浏览器只跟 client-app 说话，client-app 后台带着 token 去 9000 拿数据，
 * 再把结果渲染进页面。GitHub 案例同理：拉头像永远是网站后台拿 token
 * 去调 GitHub API，而不是把 token 发给浏览器让它自己调。
 */
@RestController
public class HomeController {

    /** auth-server 地址：client-app 后台调接口的"上游" */
    private static final String AUTH_SERVER = "http://localhost:9000";

    private final RestClient restClient = RestClient.create();

    /**
     * 查询已授权客户端的服务：登录后按 (registrationId, principalName) 从会话关联的
     * 存储里取出装着 access/refresh token 的 OAuth2AuthorizedClient。
     * 注意：不用 @RegisteredOAuth2AuthorizedClient 注解参数——匿名访问首页时
     * 它会尝试"现做一次授权"，对没登录的访客抛认证异常，导致首页直接被
     * 重定向去授权页。改用本服务，只有登录后（user != null）才去查询。
     */
    private final OAuth2AuthorizedClientService authorizedClientService;

    public HomeController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/")
    public String home(
            // 没登录时这里为 null；登录后是 JwtClaimsUserService 解析出的用户（claims 就是 token 内容）
            @AuthenticationPrincipal OAuth2User user,
            // 当前请求的完整认证信息（登录后 principalName 用于查已授权客户端）
            Authentication authentication) {

        if (user == null) {
            // 没登录：只显示登录按钮。点击进入 /oauth2/authorization/client-app
            // （Spring 客户端发起授权的固定入口，带 PKCE 的 302 就从这里发出）
            return "<h1>client-app（第三方应用）</h1>"
                    + "<p>本应用演示完整的 OAuth2 授权码 + PKCE 流程。</p>"
                    + "<p><a href=\"/oauth2/authorization/client-app\">用 auth-server 登录</a></p>";
        }

        // 已登录：取出装着 access/refresh token 的已授权客户端
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient("client-app", authentication.getName());

        // 后端代理调两个资源接口，把结果原样展示
        String meJson = callApi(client, "/api/me");
        String balanceJson = callApi(client, "/api/balance");

        return "<h1>client-app（第三方应用）</h1>"
                + "<p>你好，<b>" + escape(user.getName()) + "</b> —— 用户名来自 access token 的 sub 声明，"
                + "整个登录过程你没把密码交给过 client-app。</p>"
                + "<h2>个人信息（后端代理调 GET /api/me）</h2><pre>" + escape(meJson) + "</pre>"
                + "<h2>余额（后端代理调 GET /api/balance，要求 scope=balance:read）</h2>"
                + "<pre>" + escape(balanceJson) + "</pre>"
                + "<p><a href=\"/logout\">退出登录</a></p>";
    }

    /**
     * 后端代理调用：从已授权客户端里取 access token，带 Bearer 头去调 auth-server。
     * 如果 access token 已过期且会话里有 refresh token，框架会在调用前自动续期
     * （这正是 Step 6 要体验的"自动续期"，这里无需写任何续期代码）。
     * scope 不足时 auth-server 返回 403，这里捕获后原样展示，Step 6 会模拟这个场景。
     */
    private String callApi(OAuth2AuthorizedClient client, String path) {
        if (client == null) {
            return "（尚未授权，没有可用的 access token）";
        }
        try {
            return restClient.get()
                    .uri(AUTH_SERVER + path)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + client.getAccessToken().getTokenValue())
                    .retrieve()
                    .body(String.class);
        } catch (HttpStatusCodeException e) {
            return "调用失败：HTTP " + e.getStatusCode().value() + " " + e.getResponseBodyAsString();
        }
    }

    /** 简单转义，防止 JSON 里的尖括号破坏页面结构（demo 从简，不用完整 HTML 转义） */
    private String escape(String s) {
        return s == null ? "" : s.replace("<", "&lt;").replace(">", "&gt;");
    }
}
