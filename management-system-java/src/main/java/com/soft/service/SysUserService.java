package com.soft.service;

import com.soft.entity.SysUser;

import java.util.Set;

/**
 * 用户管理
 * @author suphowe
 */
public interface SysUserService {

    /**
     * 根据用户名查找用户
     * @param username
     * @return
     */
    SysUser findByUsername(String username);

    /**
     * 查找用户的菜单权限标识集合
     * @param username 用户名
     * @return
     */
    Set<String> findPermissions(String username);
}
