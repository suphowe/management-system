package com.soft.utils;

import java.util.UUID;

/**
 * 密码加密工具
 * @author suphowe
 */
public class PasswordUtils {

    /**
     * 匹配密码
     * @param rawPass 明文
     * @param encPass 密文
     * @return boolean
     */
    public static boolean matches(String salt, String rawPass, String encPass) {
        return new PasswordEncoder(salt).matches(encPass, rawPass);
    }

    /**
     * 明文密码加密
     * @param rawPass 明文
     * @param salt 盐
     * @return String
     */
    public static String encode(String rawPass, String salt) {
        return new PasswordEncoder(salt).encode(rawPass);
    }

    /**
     * 获取加密盐
     * @return String
     */
    public static String getSalt() {
        return UUID.randomUUID().toString().replaceAll("-", "").substring(0, 20);
    }
}
