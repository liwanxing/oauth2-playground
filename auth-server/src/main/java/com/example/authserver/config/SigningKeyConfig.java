package com.example.authserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 签名密钥配置：给 access token 防伪的"公章"。
 *
 * 注意：本文件不负责"生成 token"——token 的生成发生在 /oauth2/token 端点，
 * 由授权服务器框架完成；这里只提供生成/验证环节都要用的 RSA 密钥对。
 *
 * 对应 GitHub 案例：GitHub 发的 token 别人伪造不了，是因为 GitHub 用只有
 * 它自己有的私钥给 token 签名；你的网站验证 token 真伪时用的是 GitHub
 * 公布的公钥，接触不到私钥。
 *
 * 本文件就是本地版的这套机制：access token 实际是一个 JWT（三段式字符串），
 * 用这里生成的 RSA 私钥签名；/oauth2/jwks 端点公布公钥，
 * 资源服务器（ResourceServerConfig）用它验签——这就是"token 防伪造"的原理。
 *
 * demo 每次重启生成新密钥（旧 token 全部失效），生产环境应持久化密钥。
 */
@Configuration
public class SigningKeyConfig {

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
}
