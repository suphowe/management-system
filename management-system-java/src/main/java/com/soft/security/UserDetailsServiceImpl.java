package com.soft.security;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.soft.entity.SysUser;
import com.soft.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 用户登录认证信息查询
 * @author suphowe
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private SysUserService sysUserService;

    // UserDetailsService 接口只有一个方法,loadUserByUsername(String username),一般需要我们实现此接口方法,
    // 根据用户名加载登录认证和访问授权所需要的信息,并返回一个 UserDetails的实现类,后面登录认证和访问授权都需要用到此中的信息

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        SysUser sysUser = sysUserService.findByUsername(username);
        if (sysUser == null) {
            throw new UsernameNotFoundException("该用户不存在");
        }
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
        Set<String> permissions = sysUserService.findPermissions(username);
        List<GrantedAuthority> grantedAuthorities = permissions.stream().map(GrantedAuthorityImpl::new).collect(Collectors.toList());
        return new JwtUserDetails(sysUser.getUsername(), sysUser.getPassword(), sysUser.getSalt(), grantedAuthorities);
    }
}
