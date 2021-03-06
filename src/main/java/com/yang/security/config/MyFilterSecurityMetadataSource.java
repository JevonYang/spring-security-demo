package com.yang.security.config;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * @author https://www.jianshu.com/p/0a06496e75ea
 * @description 用于初始化url权限数据RequestMap，可以在构造函数中初始化加入持久化层读数据
 */
public class MyFilterSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

    /**
     * 这个例子放在构造方法里初始化url权限数据，我们只要保证在 getAttributes()之前初始好数据就可以了
     * 在这里，手工加载了几个对应的权限信息，也可以在这里从持久化层读取，如MySQL、MongoDB
     */
    public MyFilterSecurityMetadataSource() {
        Map<RequestMatcher, Collection<ConfigAttribute>> map = new HashMap<>();
        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/hello","GET");
        SecurityConfig config = new SecurityConfig("ROLE_ADMIN");
        Set<ConfigAttribute> configs = new HashSet<>();
        configs.add(config);
        map.put(matcher,configs);

        AntPathRequestMatcher matcher2 = new AntPathRequestMatcher("/test", "GET");
        SecurityConfig config2 = new SecurityConfig("ROLE_ADMIN");
        Set<ConfigAttribute> configs2 = new HashSet<>();
        configs2.add(config2);
        map.put(matcher2,configs2);

        this.requestMap = map;
    }

    /**
     * 在我们初始化的权限数据中找到对应当前url的权限数据
     *
     * @param object
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        FilterInvocation fi = (FilterInvocation) object;
        HttpServletRequest request = fi.getRequest();
        String url = fi.getRequestUrl();
        String httpMethod = fi.getRequest().getMethod();

        //遍历我们初始化的权限数据，找到对应的url对应的权限
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }
}
