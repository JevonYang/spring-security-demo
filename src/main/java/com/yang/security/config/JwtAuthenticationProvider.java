package com.yang.security.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 在AuthenticationManager维护着List<AuthenticationProvider>，
 * 当调用AuthenticationManger.authenticate时,会通过下面的supports的方法判断是否处理该实现，如果返回true则通过authentication处理。
 *
 * @author jevon
 * @date 2018/10/10
 * @description AuthenticationProvider用来处理AuthenticationToken，将处理特定的实现，将其转换成Authentication
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

  /**
   * 在这里直接将传过来的Authentication直接返回，是因为绝大数工作在JwtAuthenticationFilter中已经完成。
   *
   * @param authentication
   * @return Authentication
   * @throws AuthenticationException
   */
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    return authentication;
  }

  /**
   * @param authentication
   * @return 是否处理该AuthenticationToken实现，如果是响应的实现，则会用上面的authentication处理
   */
  @Override
  public boolean supports(Class<?> authentication) {
    return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
  }
}
