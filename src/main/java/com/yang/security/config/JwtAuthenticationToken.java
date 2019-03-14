package com.yang.security.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author jevon
 */
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    public JwtAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal= principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public void setAuthenticated(boolean authenticated) throws IllegalArgumentException {
        if (authenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials=null;
    }
}
