package com.yang.security.config;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.yang.security.model.User;
import com.yang.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * @author jevon
 * @date 2018/10/10
 * @description 认证jwt权限
 */

public class JwtAuthorizationTokenFilter extends AbstractAuthenticationProcessingFilter {

    @Autowired
    private JwtUtil jwtUtil;

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();


    public JwtAuthorizationTokenFilter(RequestMatcher matcher) {
        super(matcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        return null;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        if (!Pattern.matches("/auth/.*", httpServletRequest.getRequestURI()) && !"/error".equals(httpServletRequest.getRequestURI())) {
            try {
                String token = httpServletRequest.getHeader("Authorization");
                User user = jwtUtil.accessToken2User(token);
                JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(user, token, user.getAuthorities());
                final Authentication authentication = getAuthenticationManager().authenticate(authenticationToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (JWTVerificationException ex) {
                logger.warn(User.class, ex);
                throw new AuthenticationServiceException(
                        "Authentication token is invalid!");
            }
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
