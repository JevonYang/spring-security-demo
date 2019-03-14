package com.yang.security.handler;

import com.auth0.jwt.algorithms.Algorithm;
import com.yang.security.model.LoginSuccessInfo;
import com.yang.security.model.User;
import com.yang.security.model.UserHint;
import com.yang.security.utils.JwtUtil;
import com.yang.security.utils.UserHintUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

/**
 * @author jevon
 */
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Autowired
  private Algorithm algorithm;

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    User user = (User) authentication.getPrincipal();
    long expiresIn = System.currentTimeMillis() + 30 * 60 * 1000;
    String accessToken = JwtUtil.generateAccessToken(user);
    String refreshToken = UUID.randomUUID().toString().replaceAll("-", "");
    UserHintUtil.userHintInformation(response, HttpServletResponse.SC_OK, new LoginSuccessInfo("bearer "+accessToken, refreshToken, "bearer", expiresIn));
  }
}
