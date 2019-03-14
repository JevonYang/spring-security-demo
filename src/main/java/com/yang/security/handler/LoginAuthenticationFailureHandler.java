package com.yang.security.handler;

import com.yang.security.utils.UserHintUtil;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author jevon
 */
public class LoginAuthenticationFailureHandler implements AuthenticationFailureHandler {
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    UserHintUtil.userHintInformation(response, HttpServletResponse.SC_UNAUTHORIZED, exception.getMessage());
  }
}
