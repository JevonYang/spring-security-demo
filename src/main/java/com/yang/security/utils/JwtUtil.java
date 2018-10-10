package com.yang.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.yang.security.config.JwtAuthenticationToken;
import com.yang.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Component
public class JwtUtil {

    @Autowired
    private Algorithm algorithm;

    public String User2accessToken(User user) {
        long halfHourLater = System.currentTimeMillis() + 30 * 60 * 1000;
        return JWT.create()
                .withIssuer("jevon")
                .withSubject(user.getCompany())
                .withAudience(user.getUsername())
                .withExpiresAt(new Date(halfHourLater))
                .withIssuedAt(new Date())
                .withClaim("id",user.getId())
                .withClaim("department",user.getDepartment())
                .withArrayClaim("Authorities",user.getAuthoritiesToString())
                .sign(algorithm);
    }

    public User AccessToken2User(String accessToken) {
        try{
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("jevon")
                    .build();
            DecodedJWT jwt = verifier.verify(accessToken);
            String[] authorities = jwt.getClaim("Authorities").asArray(String.class);
            Set<GrantedAuthority> set = new HashSet<>();
            for (int i = 0; i < authorities.length; i++) {
                GrantedAuthority authority = new SimpleGrantedAuthority(authorities[i]);
                set.add(authority);
            }
            Map<String, Claim> map = jwt.getClaims();
            String userDetails= jwt.getPayload();
            return new User(jwt.getClaim("id").asLong(),
                    jwt.getAudience().get(0),
                    jwt.getSubject(),
                    jwt.getClaim("department").asString(),
                    set
                    );
        } catch (JWTVerificationException e) {
            // do something
        }
        return null;

    };
}
