package com.soft.security;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * 自定义令牌对象
 * @author suphowe
 */
public class JwtAuthenticatioToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private String token;

    public JwtAuthenticatioToken(Object principal, Object credentials){
        super(principal, credentials);
    }

    public JwtAuthenticatioToken(Object principal, Object credentials, String token){
        super(principal, credentials);
        this.token = token;
    }

    public JwtAuthenticatioToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String token) {
        super(principal, credentials, authorities);
        this.token = token;
    }

    /**
     * 获取token
     * @return token
     */
    public String getToken() {
        return token;
    }

    /**
     * JwtAuthenticatioToken中放入令牌
     * @param token 令牌
     */
    public void setToken(String token) {
        this.token = token;
    }

    public static long getSerialversionuid() {
        return serialVersionUID;
    }

}

