package com.yang.security.config;

import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.regex.Pattern;

/**
 * @author jevon
 * @date 2018/10/11
 * @description
 */
public class SkipUrlMatcher implements RequestMatcher {

    private List<String> skipPattern;

    public SkipUrlMatcher(List<String> skipPattern) {
        this.skipPattern = skipPattern;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        for (String item:skipPattern) {
            if (Pattern.matches(item, request.getRequestURI())) {
                return false;
            }
        }
        return true;
    }
}
