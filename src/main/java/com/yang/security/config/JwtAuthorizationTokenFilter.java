package com.yang.security.config;

import com.yang.security.model.User;
import com.yang.security.utils.JwtUtil;
import com.yang.security.utils.UserHintUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
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
@Slf4j
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

    try {
      // Step1. 将token转换成UserDetails(这里的User是自己写的UserDetail的实现)
      User user = JwtUtil.accessToken2User(token.substring(7));
      log.info(user.toString());

      // Step2. 将UserDetails转换成Authentication，这里的JwtAuthenticationToken即为Authentication的实现，
      // 一般而言，将UserDetails放入Authentication的principle中,之后如果需要可通过Authentication.getPrinciple的方法把UserDetails取出来
      JwtAuthenticationToken authenticationToken = new JwtAuthenticationToken(user, token, user.getAuthorities());

      // Step3. 这一步将AuthenticationToken交由AuthenticationProvider处理，转换成Authentication
      final Authentication authentication = getAuthenticationManager().authenticate(authenticationToken);

      // Step4. 将得到的Authentication实例放入Holder，则认证完成
      SecurityContextHolder.getContext().setAuthentication(authentication);

      // Step5. 进入之后的过滤器处理
      filterChain.doFilter(httpServletRequest, httpServletResponse);
    } catch (NullPointerException e) {
      if (log.isDebugEnabled()) {
        e.printStackTrace();
      }
      // 如果出现没有携带token的情况，直接返回401（根据需要的业务逻辑来处理）
      UserHintUtil.userHintInformation((HttpServletResponse) response, HttpServletResponse.SC_UNAUTHORIZED, "拒绝访问");

    } catch (IOException e) {
      e.printStackTrace();
    } catch (ServletException e) {
      e.printStackTrace();
    }
  }
}
