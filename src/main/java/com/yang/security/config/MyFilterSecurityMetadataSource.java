package com.yang.security.config;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class MyFilterSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    private final Map<RequestMatcher, Collection<ConfigAttribute>> requestMap;

    /**
     * 这个例子放在构造方法里初始化url权限数据，我们只要保证在 getAttributes()之前初始好数据就可以了
     */
    public MyFilterSecurityMetadataSource() {
        Map<RequestMatcher, Collection<ConfigAttribute>> map = new HashMap<>();

        AntPathRequestMatcher matcher = new AntPathRequestMatcher("/hello","GET");

        SecurityConfig config = new SecurityConfig("ROLE_ADMIN");
        Set<ConfigAttribute> configs = new HashSet<>();
        configs.add(config);
        map.put(matcher,configs);

        AntPathRequestMatcher matcher2 = new AntPathRequestMatcher("/", "GET");
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

        // Lookup your database (or other source) using this information and populate the
        // list of attributes (这里初始话你的权限数据)
        //List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>();

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
