package com.soft.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 身份验证提供者
 * @author suphowe
 */
public class JwtAuthenticationProvider extends DaoAuthenticationProvider {

    // 关系 DaoAuthenticationProvider --继承--> AbstractUserDetailsAuthenticationProvider --实现--> AuthenticationProvider

    public JwtAuthenticationProvider(UserDetailsService userDetailsService) {
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(new BCryptPasswordEncoder());
    }

    /**
     * 登陆认证逻辑
     * @param authentication 需要认证信息
     * @return 认证信息
     * @throws AuthenticationException 认证异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 通过 AbstractUserDetailsAuthenticationProvider 中的 retrieveUser 获取验证信息
        // 在 DaoAuthenticationProvider 中重写该方法,通过 UserDetailsService 获取验证信息
        // UserDetailsService 接口只有一个方法,loadUserByUsername(String username),一般需要我们实现此接口方法,
        // 根据用户名加载登录认证和访问授权所需要的信息,并返回一个 UserDetails的实现类,后面登录认证和访问授权都需要用到此中的信息
        // 可以在此处覆写整个登录认证逻辑
        return super.authenticate(authentication);
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        // 可以在此处覆写密码验证逻辑
        super.additionalAuthenticationChecks(userDetails, authentication);
    }

}
