# oauth2-playground

用两个最小化的 Spring Boot 项目，一步步亲手体验 OAuth2 授权码流程（Authorization Code + PKCE）。

## 项目结构

```
oauth2-playground/
├── auth-server/    授权服务器 + 资源服务器（端口 9000）
│                   登录页、发 token、个人信息接口 /api/me、余额接口 /api/balance
└── client-app/     第三方客户端应用（端口 8000）
                    发起授权跳转、用授权码换 token、拿 token 调余额接口
```

## 角色对应关系

| OAuth2 标准角色 | 本仓库中的实现 |
|---|---|
| Resource Owner（用户） | 浏览器里的你 |
| Client（第三方应用） | client-app |
| Authorization Server | auth-server 的登录/授权/token 端点 |
| Resource Server | auth-server 的 /api/me、/api/balance |

注意：本 demo 把授权服务器和资源服务器放在同一个应用里，这是学习时最常见的简化；
生产环境中它们通常分开部署。

## 学习路线（每完成一步提交一次 git，可对照 diff 理解）

- [ ] Step 1：auth-server 骨架（Spring Boot + Spring Authorization Server 依赖）
- [ ] Step 2：授权服务器配置 —— 写死一个登录用户、注册 client-app、授权码 + PKCE
- [ ] Step 3：资源服务器 —— /api/me（个人信息）和 /api/balance（mock 余额 + scope 校验）
- [ ] Step 4：client-app 骨架（Spring Security OAuth2 Client）
- [ ] Step 5：客户端首页 → 跳转授权 → 拿 token → 调余额接口
- [ ] Step 6：体验 refresh token 自动续期、scope 不足被 403

## 怎么跑

前置要求：JDK 17+（本机是 Java 25）、Maven 3.9+。

```bash
# 终端 1：先启动授权服务器
cd auth-server && mvn spring-boot:run

# 终端 2：再启动客户端
cd client-app && mvn spring-boot:run
```

然后浏览器打开 http://localhost:8000 ，点击"用 auth-server 账号登录"，
会跳到 http://localhost:9000 的登录页（账号在 Step 2 的配置里写死），
登录并同意授权后跳回客户端，即可看到你的个人信息和 mock 余额。

## 写死的数据（后续步骤会用到）

- 登录用户：`user` / 密码在配置文件里（demo 用途，无安全性）
- 余额接口返回：mock 的账户余额 JSON
- scope 约定：`balance:read` 才能读余额
