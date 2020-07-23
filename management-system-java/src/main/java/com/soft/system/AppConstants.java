package com.soft.system;

import com.soft.utils.SysUtils;

/**
 * 系统静态数据
 * @author suphowe
 */
public class AppConstants {

    /**
     * 访问授权白名单
     */
    public static String[] WHITE_LIST = SysUtils.getProperties("system/appconstants", "WHITE_LIST").split(",");

    /**
     * druid管理访问IP白名单
     */
    public static String[] DRUID_ALLOWS = SysUtils.getProperties("system/appconstants", "DRUID_ALLOWS").split(",");

    /**
     * druid管理访问IP黑名单
     */
    public static String[] DRUID_DENYS = SysUtils.getProperties("system/appconstants", "DRUID_DENYS").split(",");

    /**
     * druid管理用户名
     */
    public static String DRUID_LOGINUSERNAME = SysUtils.getProperties("system/appconstants", "DRUID_LOGINUSERNAME");

    /**
     * druid管理密码
     */
    public static String DRUID_LOGINPASSWORD = SysUtils.getProperties("system/appconstants", "DRUID_LOGINPASSWORD");

}
