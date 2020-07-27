package com.soft.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import com.soft.bean.LoginBean;
import com.soft.http.HttpResult;
import com.soft.security.JwtAuthenticatioToken;
import com.soft.utils.SecurityUtils;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.*;

/**
 * 登录控制器
 * @author suphowe
 */
@CrossOrigin
@RestController
@Api(value = "Frontal Login")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 登录接口
     */
    @ResponseBody
    @RequestMapping(value ="/login", method= RequestMethod.POST)
    @ApiOperation(value="用户登陆")
    public HttpResult login(@RequestBody LoginBean loginBean, HttpServletRequest request) throws IOException {
        String username = loginBean.getUsername();
        String password = loginBean.getPassword();

        // 系统登录认证
        JwtAuthenticatioToken token = SecurityUtils.login(request, username, password, authenticationManager);

        return HttpResult.ok(token);
    }

}
