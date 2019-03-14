package com.yang.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yang.security.model.MyGrantedAuthority;
import com.yang.security.model.User;
import org.springframework.security.core.GrantedAuthority;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * @author jevon
 */
public class JwtUtil {

  public static String generateAccessToken(User user) {
    long halfHourLater = System.currentTimeMillis() + 30 * 60 * 1000;
    return JWT.create()
        // 签发者
        .withIssuer("jevon")
        // 面向用户
        .withSubject(user.getCompany())
        // 接收方，一般为用户名
        .withAudience(user.getUsername())
        // 过期时间
        .withExpiresAt(new Date(halfHourLater))
        // 签发时间
        .withIssuedAt(new Date())
        // 一些自定的字段，和JwtAuthenticationTokenFilter（自定义的）逻辑相关
        // 个人理解： 能够将Jwt和spring security内部的UserDetail能够相互转换即可
        // 通过JwtAuthenticationTokenFilter将Jwt转换成SpringSecurity内部的UserDetail或者说Authentication
        .withClaim("id", user.getId())
        .withClaim("company", user.getCompany())
        .withClaim("department", user.getDepartment())
        .withArrayClaim("Authorities", user.getAuthorityList())
        .sign(Algorithm.HMAC256("hello"));
  }

  public static User accessToken2User(String accessToken) {
    try {
      JWTVerifier verifier = JWT.require(Algorithm.HMAC256("hello"))
          .withIssuer("Jevon")
          .build();
      DecodedJWT jwt = verifier.verify(accessToken);
      String[] authorities = jwt.getClaim("Authorities").asArray(String.class);
      Set<GrantedAuthority> authoritySet = new HashSet<>();
      for (int i = 0; i < authorities.length; i++) {
        authoritySet.add(new MyGrantedAuthority(authorities[i]));
      }
      return new User(jwt.getClaim("id").asLong(),
          jwt.getAudience().get(0),
          null,
          jwt.getSubject(),
          jwt.getClaim("department").asString(),
          null,
          null,
          authoritySet);
    } catch (JWTVerificationException e) {
      e.printStackTrace();
    }
    return null;
  }

  ;
}
