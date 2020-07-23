package com.soft.security;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * 安全用户模型
 * @author suphowe
 */
public class JwtUserDetails extends User {

    // User为UserDetails默认实现的User,主要包含用户名(username),密码(password),权限(authorities)和一些账号或密码状态的标识
    // 根据需求定制自己的 UserDetails,然后在 UserDetailsService 的 loadUserByUsername 中返回即可

    private static final long serialVersionUID = 1L;

    public JwtUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, true, true, true, true, authorities);
    }

    public JwtUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
                          boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

}
