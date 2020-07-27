package com.soft.service.impl;

import com.soft.entity.SysUser;
import com.soft.service.SysUserService;
import com.soft.utils.PasswordEncoder;
import com.soft.utils.PasswordUtils;
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
        String salt = PasswordUtils.getSalt();
        String password = new PasswordEncoder(salt).encode("123");
        SysUser sysUser = new SysUser();
        sysUser.setId(1L);
        sysUser.setUsername(username);
        sysUser.setPassword(password);
        sysUser.setSalt(salt);
        return sysUser;
    }
}
