package com.yang.security.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.yang.security.model.User;
import com.yang.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jevon
 * @date 2018/10/10
 * @description 认证jwt权限
 */

@Component
public class JwtAuthorizationTokenFilter extends GenericFilterBean {

    //private Logger logger = LoggerFactory.getLogger(JwtAuthorizationTokenFilter.class);

    @Autowired
    private Algorithm algorithm;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        try {
            String token = httpServletRequest.getHeader("Authorization");
            User user = jwtUtil.AccessToken2User(token);
            JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(user, null, user.getAuthorities());
            final Authentication authentication = authenticationManager.authenticate(authenticationToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JWTVerificationException e) {
            logger.error("jwt失效");
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
