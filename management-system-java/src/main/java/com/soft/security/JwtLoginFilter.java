package com.soft.security;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.soft.utils.HttpUtils;
import com.soft.utils.JwtTokenUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;

/**
 * 启动登录认证流程过滤器(接口访问权限)
 * @author suphowe
 */
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {

    //通过URL方式的接口访问控制和方法调用的权限控制
    //浏览器使用URL访问后台接口时,是否允许访问此URL,就是接口访问权限
    //接口访问授权,也就是 FilterSecurityInterceptor 管理的URL授权,默认对应的授权策略只有一个,就是 WebExpressionVoter,
    //它的授权策略主要是根据 WebSecurityConfigurerAdapter 内配置的路径访问策略进行匹配,然后决定是否授权

    private static final Logger logger = LoggerFactory.getLogger(JwtLoginFilter.class);

    /**
     * 初始化过滤器
     * @param authenticationManager 认证管理器
     */
    public JwtLoginFilter(AuthenticationManager authenticationManager) {
        setAuthenticationManager(authenticationManager);
    }

    /**
     * 过滤器
     * 在进行接口访问时,会由 FilterSecurityInterceptor 进行拦截并进行授权
     * FilterSecurityInterceptor 继承了 AbstractSecurityInterceptor 并实现了 javax.servlet.Filter 接口,所以在URL访问的时候都会被过滤器拦截
     * doFilter 方法又调用了自身的 invoke 方法,invoke 方法又调用了父类 AbstractSecurityInterceptor 的 beforeInvocation 方法
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        logger.info("访问uri--->{}", httpServletRequest.getRequestURI());
        // POST 请求 /login 登录时拦截， 由此方法触发执行登录认证流程，可以在此覆写整个登录认证逻辑
        // UsernamePasswordAuthenticationFilter 中绑定 /login POST 方法,但访问/login时,
        // /login 由UsernamePasswordAuthenticationFilter 继承的 AbstractAuthenticationProcessingFilter 类中的doFilter进行处理
        super.doFilter(httpServletRequest, httpServletResponse, filterChain);
    }

    /**
     * 登陆认证逻辑(重写 AbstractAuthenticationProcessingFilter 中的 attemptAuthentication 逻辑)
     * @param httpServletRequest 接收信息
     * @param httpServletResponse 返回信息
     * @return 认证信息
     * @throws AuthenticationException 认证异常
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException {
        // 可以在此覆写尝试进行登录认证的逻辑，登录成功之后等操作不再此方法内
        // 如果使用此过滤器来触发登录认证流程，注意登录请求数据格式的问题
        // 此过滤器的用户名密码默认从request.getParameter()获取，但是这种
        // 读取方式不能读取到如 application/json 等 post 请求数据，需要把
        // 用户名密码的读取逻辑修改为到流中读取request.getInputStream()
        String body = getBody(httpServletRequest);
        JSONObject jsonObject = JSON.parseObject(body);
        String username = jsonObject.getString("username");
        String password = jsonObject.getString("password");

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }
        username = username.trim();

        // Spring Security的登录认证过程是委托给 AuthenticationManager 完成的,它先是解析出用户名和密码,
        // 然后把用户名和密码封装到一个UsernamePasswordAuthenticationToken 中,
        // 传递给 AuthenticationManager,交由 AuthenticationManager 完成实际的登录认证过程
        JwtAuthenticatioToken jwtAuthenticatioToken = new JwtAuthenticatioToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(httpServletRequest, jwtAuthenticatioToken);

        return this.getAuthenticationManager().authenticate(jwtAuthenticatioToken);
    }

    /**
     * 登陆认证成功(重写 AbstractAuthenticationProcessingFilter 中的 successfulAuthentication 逻辑)
     * @param request 接收信息
     * @param response 返回信息
     * @param filterChain 过滤器
     * @param authResult 认证信息
     * @throws IOException IO异常
     * @throws ServletException Servlet异常
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
                                            Authentication authResult) throws IOException, ServletException {
        // 存储登录认证信息到上下文
        // 登录成功之后,将认证后的 Authentication 对象存储到请求线程上下文,
        // 这样在授权阶段就可以获取到 Authentication 认证信息,并利用 Authentication 内的权限信息进行访问控制判断
        SecurityContextHolder.getContext().setAuthentication(authResult);
        // 记住我服务
        getRememberMeServices().loginSuccess(request, response, authResult);
        // 触发事件监听器
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }
        // 生成并返回token给客户端，后续访问携带此token
        JwtAuthenticatioToken token = new JwtAuthenticatioToken(null, null, JwtTokenUtils.generateToken(authResult));
        HttpUtils.write(response, token);
    }

    /** 
     * 获取请求Body
     * @param httpServletRequest 接受信息
     * @return 请求body
     */
    public String getBody(HttpServletRequest httpServletRequest) {
        StringBuilder result = new StringBuilder();
        InputStream inputStream = null;
        BufferedReader reader = null;
        try {
            inputStream = httpServletRequest.getInputStream();
            reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("UTF-8")));
            String line = "";
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return result.toString();
    }
}
