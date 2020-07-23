package com.soft.utils;

import com.alibaba.fastjson.JSON;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.*;

public class SysUtils {

    /**
     * 返回一个uuid
     *
     * @return
     */
    public static String getUUID() {
        String struuid = UUID.randomUUID().toString();
        return struuid.substring(0, 8) + struuid.substring(9, 13)
                + struuid.substring(14, 18) + struuid.substring(19, 23)
                + struuid.substring(24);
    }

    public static String getUUID16() {
        String struuid = UUID.randomUUID().toString();
        return struuid.substring(0, 8) + struuid.substring(9, 13)
                + struuid.substring(14, 18);
    }

    public static String getProperties(String filename,String param){
        ResourceBundle rb=ResourceBundle.getBundle(filename);
        return rb.getString(param).trim();
    }

    public static String getRemoteHost(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip.equals("0:0:0:0:0:0:0:1") ? "127.0.0.1" : ip;
    }

    /**
     * 把字符串数组转换成浮点数组
     * @param arr
     * @return
     */
    public static float[] strToFloat(String[] arr){
        if(arr.length == 0){
            return null;
        }
        float[] floats = new float[arr.length];
        for (int i = 0; i < arr.length; i++) {
            floats[i] = Float.valueOf(arr[i]);
        }
        return floats;
    }

    /**
     * 把字符串转换成浮点数组
     * @param str
     * @return
     */
    public static float[] stringToFloat(String str){
        if(str==null||str.equals("")){
            return null;
        }
        String[] arr = str.split(",");
        float[] floats = new float[arr.length];
        for (int i = 0; i < arr.length; i++) {
            floats[i] = Float.valueOf(arr[i]);
        }
        return floats;
    }

    /**
     * 将JSON转换成List
     * @param text
     * @return
     */
    public static List<Object> jsonToList(String text){
        if(text==null || text.equals("")){
            return null;
        }
        return JSON.parseObject(text, List.class);
    }

    public static String getThisServerIp(){
        String ip = "";
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                NetworkInterface intf = en.nextElement();
                String name = intf.getName();
                if (!name.contains("docker") && !name.contains("lo")) {
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress()) {
                            String ipaddress = inetAddress.getHostAddress().toString();
                            if (!ipaddress.contains("::") && !ipaddress.contains("0:0:") && !ipaddress.contains("fe80")) {
                                ip = ipaddress;
                            }
                        }
                    }
                }
            }
        } catch (SocketException ex) {
            ip = "127.0.0.1";
            ex.printStackTrace();
        }
        return ip;
    }
}
