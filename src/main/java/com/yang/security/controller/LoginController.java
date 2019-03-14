package com.yang.security.controller;

import com.auth0.jwt.algorithms.Algorithm;
import com.yang.security.model.LoginEntity;
import com.yang.security.model.LoginSuccessInfo;
import com.yang.security.model.User;
import com.yang.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jevon
 * @date 2018/10/09
 * @description 登入、登出、刷新token入口
 */
@RestController
@RequestMapping(value = "/user")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

//    @RequestMapping(value = "/login", method = RequestMethod.POST)
//    public LoginSuccessInfo login(@RequestBody LoginEntity user) throws AuthenticationException {
//        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
//        final Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//        final User currentUser = (User) authentication.getPrincipal();
//        long halfHourLater = System.currentTimeMillis() + 30 * 60 * 1000;
//        String accessToken = JwtUtil.generateAccessToken(currentUser);
//        return new LoginSuccessInfo(accessToken, accessToken, "JWT", halfHourLater);
//    };

    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public String logout() {
        // write your logout logic
        return "hello, world!";
    };


    @RequestMapping(value = "/refresh", method = RequestMethod.POST)
    public String refresh() {
        // write your refresh token logic
        return "hello, world!";
    };

}
