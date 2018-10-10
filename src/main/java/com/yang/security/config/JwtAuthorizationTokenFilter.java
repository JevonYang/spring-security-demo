package com.yang.security.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author jevon
 * @date 2018/10/10
 * @description 认证jwt权限
 */
public class JwtAuthorizationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private Algorithm algorithm;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token = httpServletRequest.getHeader("Authorization");
        try {
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("jevon")
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            String userDetails= jwt.getPayload();
            List<GrantedAuthority> list = new ArrayList<>();
            JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(userDetails, null, list);
            final Authentication authentication = authenticationManager.authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JWTVerificationException exception){
            //Invalid signature/claims
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
