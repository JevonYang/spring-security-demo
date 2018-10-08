package com.yang.security.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;

/**
 * @author jevon
 * @date 2018/10/08
 * @description 自定义的AccessDecisionVoter
 */
public class MyAccessDecisionVoter implements AccessDecisionVoter<FilterInvocation> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof MyAccessDecisionVoter;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public int vote(Authentication authentication, FilterInvocation object,
                    Collection<ConfigAttribute> attributes) {
        return 0;
    }
}
