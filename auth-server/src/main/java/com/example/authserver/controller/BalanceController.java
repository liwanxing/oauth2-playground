package com.example.authserver.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Step 3：余额接口（mock 数据）——重点演示"验章"之后的第二步"查权限"。
 *
 * 验章（token 是真的）和查权限（token 允许干这件事）是两个不同的检查：
 * - token 是真的，但里面没有 balance:read 这个 scope -> 依然 403
 * - 这就是 OAuth2 里"最小授权"的意义：client-app 只能拿到你同意给它的那些权限
 *
 * @PreAuthorize(...)：方法执行前的权限检查（需要 ResourceServerConfig 上的
 * @EnableMethodSecurity 才生效）。规则含义：
 *   资源服务器验完 token 后，会把 token 里的每个 scope 转换成一种叫
 *   authority 的权限标记，格式为 SCOPE_ + scope 名。
 *   hasAuthority("SCOPE_balance:read") 就是"必须有 balance:read 这个权限"。
 * 不满足时 Spring 自动返回 403 Forbidden，不用手写任何判断代码。
 */
@RestController
public class BalanceController {

    @GetMapping("/api/balance")
    @PreAuthorize("hasAuthority('SCOPE_balance:read')")
    public Map<String, Object> balance() {
        // mock 数据，真实项目这里查数据库
        return Map.of(
                "account", "user 的演示账户",
                "balance", 8888.88,
                "currency", "CNY"
        );
    }
}
