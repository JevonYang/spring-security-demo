package com.yang.security.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.yang.security.model.User;
import com.yang.security.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
public class JwtAuthorizationTokenFilter extends AbstractAuthenticationProcessingFilter {

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    return null;
  }

  public JwtAuthorizationTokenFilter(RequestMatcher matcher) {
    super(matcher);
  }

  public JwtAuthorizationTokenFilter(String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws ServletException, IOException {

    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;

    if (!requiresAuthentication(httpServletRequest, httpServletResponse)) {
      filterChain.doFilter(httpServletRequest, httpServletResponse);
      return;
    }

    String token = httpServletRequest.getHeader("Authorization");
    User user = JwtUtil.accessToken2User(token);
    JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(user, token, user.getAuthorities());
    final Authentication authentication = getAuthenticationManager().authenticate(authenticationToken);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }
}
