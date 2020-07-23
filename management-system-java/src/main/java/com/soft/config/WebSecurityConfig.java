package com.soft.config;

import com.soft.security.JwtAuthenticationFilter;
import com.soft.security.JwtAuthenticationProvider;
import com.soft.security.JwtLoginFilter;
import com.soft.system.AppConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

/**
 * Security安全配置(方法调用权限)
 * @author suphowe
 * @deprecated Security方法注解的支持需要在任何配置类中如(WebSecurityConfigurerAdapter)
 *              添加 @EnableGlobalMethodSecurity(prePostEnabled = true) 开启，才能够使用
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    //通过URL方式的接口访问控制和方法调用的权限控制
    //进行后台方法调用时,是否允许该方法调用,就是方法调用权限,在进行方法调用时,会由 MethodSecurityInterceptor 进行拦截并进行授权。
    //MethodSecurityInterceptor 继承了 AbstractSecurityInterceptor 并实现了AOP 的 org.aopalliance.intercept.MethodInterceptor 接口,所以可以在方法调用时进行拦截
    //MethodSecurityInterceptor 跟 FilterSecurityInterceptor 一样,都是通过调用父类 AbstractSecurityInterceptor 的相关方法完成授权,其中 beforeInvocation 是完成权限认证的关键
    //AbstractSecurityInterceptor 又是委托授权认证器 AccessDecisionManager 完成授权认证,默认实现是 AffirmativeBased
    //AccessDecisionManager 决定授权又是通过一个授权策略集合（AccessDecisionVoter ）决定的,授权决定的原则是：
    //      1. 遍历所有授权策略,如果有其中一个返回 ACCESS_GRANTED，则同意授权
    //      2. 否则,等待遍历结束,统计 ACCESS_DENIED 个数,只要拒绝数大于1,则不同意授权
    //对于方法调用授权,在全局方法安全配置类里,
    //      可以看到给 MethodSecurityInterceptor 默认配置的有 RoleVoter、AuthenticatedVoter、Jsr250Voter和 PreInvocationAuthorizationAdviceVoter,
    //      其中 Jsr250Voter、PreInvocationAuthorizationAdviceVoter 都需要打开指定的开关,才会添加支持

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        // 指定了自定义身份认证组件 JwtAuthenticationProvider，并注入 UserDetailsService
        auth.authenticationProvider(new JwtAuthenticationProvider(userDetailsService));
    }

    /**
     * 访问路径URL的授权策略
     * 指定白名单免登陆认证
     *
     * @param http HttpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        HttpSecurity httpSecurity = http.cors().and().csrf().disable();

        // 禁用 csrf, 由于使用的是JWT，我们这里不需要csrf
        httpSecurity.authorizeRequests()
                // 跨域预检请求
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // 登录URL
                .antMatchers("/login").permitAll()
                // swagger
                .antMatchers("/swagger**/**").permitAll()
                .antMatchers("/webjars/**").permitAll()
                .antMatchers("/v2/**").permitAll();

        //从配置文件获取白名单列表
        String[] whiteList = AppConstants.WHITE_LIST;
        for (int i = 0; i < whiteList.length; i++) {
            httpSecurity.authorizeRequests().antMatchers(whiteList[i]).permitAll();
        }

        // 其他所有请求需要身份认证
        httpSecurity.authorizeRequests().anyRequest().authenticated();

        // 退出登录处理器
        // LogoutConfigurer 中配置退出url /logout
        // Spring Security 提供了一个默认的登出过滤器 LogoutFilter
        // 默认拦截路径是 /logout,当访问 /logout 路径的时候,LogoutFilter 会进行退出处理
        http.logout().logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler());

        // 开启登录认证流程过滤器,如果使用LoginController的login接口,需要注释掉此过滤器,根据使用习惯二选一即可
        // 需要进行登陆验证其他操作时,使用该过滤器,在过滤器中编写登陆逻辑
        http.addFilterBefore(new JwtLoginFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);

        // 访问控制时登录状态检查过滤器
        http.addFilterBefore(new JwtAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

}
