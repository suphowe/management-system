package com.soft.service.impl;

import com.soft.entity.SysUser;
import com.soft.service.SysUserService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class SysUserServiceImpl implements SysUserService {

    /**
     * 用户可使用的权限列表
     * @param username 用户名
     * @return 权限列表
     */
    @Override
    public Set<String> findPermissions(String username) {
        Set<String> permissions = new HashSet<>();
        permissions.add("sys:user:view");
        permissions.add("sys:user:add");
        permissions.add("sys:user:edit");
        permissions.add("sys:user:delete");
        return permissions;
    }

    /**
     * 通过用户名查找用户信息
     * @param username 用户名
     * @return 用户信息
     */
    @Override
    public SysUser findByUsername(String username) {
        SysUser sysUser = new SysUser();
        sysUser.setId(1L);
        sysUser.setUsername(username);
        String password = new BCryptPasswordEncoder().encode("123");
        sysUser.setPassword(password);
        return sysUser;
    }
}
