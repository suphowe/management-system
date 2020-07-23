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
    //  1.RoleVoter 是根据角色进行匹配授权的策略,RoleVoter  默认角色名以 "ROLE_" 为前缀,逐个角色进行匹配,入股有一个匹配得上,则进行授权
    //  2.AuthenticatedVoter 主要是针对有配置以下几个属性来决定授权的策略
    //      IS_AUTHENTICATED_REMEMBERED：记住我登录状态
    //      IS_AUTHENTICATED_ANONYMOUSLY：匿名认证状态
    //      IS_AUTHENTICATED_FULLY： 完全登录状态，即非上面两种类型
    //  3.PreInvocationAuthorizationAdviceVoter 是针对类似  @PreAuthorize("hasRole('ROLE_ADMIN')")  注解解析并进行授权的策略
    //      PreInvocationAuthorizationAdviceVoter 解析出注解属性配置,然后通过调用 PreInvocationAuthorizationAdvice 的前置通知方法进行授权认证,
    //      默认实现类似 ExpressionBasedPreInvocationAdvice,通知内主要进行了内容的过滤和权限表达式的匹配

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
                .antMatchers("/v2/**").permitAll()
                // 首页和登陆页面
                // .antMatchers("/").permitAll()
                // 其他所有请求需要身份验证
                // .anyRequest().authenticated()
                // 配置登陆认证 formLogin()返回一个FormLoginConfigurer对象,
                // FormLoginConfigurer 绑定了一个 UsernamePasswordAuthenticationFilter 过滤器
                // UsernamePasswordAuthenticationFilter 绑定了 POST 类型 /login 请求
                // 使用 POST 类型的 /login URL进行登录的时候就会被这个过滤器拦截,并进行登录验证
                // UsernamePasswordAuthenticationFilter 继承 AbstractAuthenticationProcessingFilter
                // AbstractAuthenticationProcessingFilter 中的 doFilter 包含了触发登录认证(表单登陆)执行流程的相关逻辑
                //      1.attemptAuthentication(request, response) 抽象方法,包含登陆主逻辑,由其子类实现具体登陆验证
                //      2.successfulAuthentication(request, response, chain, authResult) 登陆成功后,将认证之后的 Authentication 对象存储到请求线程上下文,
                //          这样在授权阶段就可以获取到此认证信息进行访问控制判断 SecurityContextHolder.getContext().setAuthentication(authResult);
                //          这样在授权阶段就可以获取到 Authentication 认证信息,并利用 Authentication 内的权限信息进行访问控制判断
                //          Spring Security的登录认证过程是委托给 AuthenticationManager 完成的,它先是解析出用户名和密码,
                //          然后把用户名和密码封装到一个UsernamePasswordAuthenticationToken 中,传递给 AuthenticationManager,
                //          交由 AuthenticationManager 完成实际的登录认证过程
                // AuthenticationManager 提供了一个默认的 实现 ProviderManager,而 ProviderManager 又将验证委托给了 AuthenticationProvider
                // AuthenticationProvider 衍生出多种类型的实现,AbstractUserDetailsAuthenticationProvider 是 AuthenticationProvider 的抽象实现,
                //      定义了较为统一的验证逻辑,各种验证方式可以选择直接继承 AbstractUserDetailsAuthenticationProvider 完成登录认证,
                //      如 DaoAuthenticationProvider 就是继承了此抽象类,完成了从DAO方式获取验证需要的用户信息的
                // 如上面所述， AuthenticationProvider 通过 retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) 获取验证信息,
                //      对于我们一般所用的 DaoAuthenticationProvider 是由 UserDetailsService 专门负责获取验证信息的
                // .and().formLogin().loginProcessingUrl("/login")
                ;
        //从配置文件获取白名单列表,白名单过滤
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
