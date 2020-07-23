# management-system-java 后台

## 权限整合
spring security

### 使用登录权限控制器
LoginController中使用
```aidl
// 系统登录认证
JwtAuthenticatioToken token = SecurityUtils.login(request, username, password, authenticationManager);
```
需要禁用登录认证过滤器,即将 WebSecurityConfig 中的以下配置项注释即可,否则访问登录接口会被过滤拦截,执行不会再进入此登录接口
```aidl
// 开启登录认证流程过滤器,如果使用LoginController的login接口,,需要注释掉此过滤器,根据使用习惯二选一即可
http.addFilterBefore(new JwtLoginFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
```