package com.yang.security.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yang.security.model.LoginEntity;
import com.yang.security.model.MyAuthenticatedToken;
import com.yang.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * @author jevon
 * @date 2018/10/09
 * @description 登入、登出、刷新token入口
 */
@RestController
@RequestMapping(value = "/auth")
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private Algorithm algorithm;

    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public MyAuthenticatedToken login(@RequestBody LoginEntity user) throws AuthenticationException {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        final Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        final User currentUser = (User) authentication.getPrincipal();
        long halfHourLater = System.currentTimeMillis() + 30 * 60 * 1000;
        String accessToken = JWT.create()
                .withIssuer("jevon")
                .withSubject(currentUser.getAuthorities().iterator().next().toString())
                .withAudience(currentUser.getUsername())
                .withExpiresAt(new Date(halfHourLater))
                .withIssuedAt(new Date())
                .sign(algorithm);
        return new MyAuthenticatedToken(accessToken, accessToken, "JWT", halfHourLater);
    };

    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public String logout() {

        return "hello, world!";
    };



    @RequestMapping(value = "/refresh", method = RequestMethod.POST)
    public String refresh() {

        return "hello, world!";
    };

    public static void main(String[] args) {
//        String jwt = JWT.create().withIssuer("yang").withSubject("unicom").withAudience("username").withExpiresAt(new Date()).sign(algorithm);
//        System.out.println("jwt: "+ jwt);
//        JWTVerifier verifier = JWT.require(algorithm)
//                .withIssuer("yang")
//                .build(); //Reusable verifier instance
//        DecodedJWT token = verifier.verify(jwt);
    }

}
