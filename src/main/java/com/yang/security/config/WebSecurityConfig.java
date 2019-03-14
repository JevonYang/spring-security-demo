package com.yang.security.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.yang.security.handler.LoginAuthenticationFailureHandler;
import com.yang.security.handler.LoginAuthenticationSuccessHandler;
import com.yang.security.service.MyUserDetailsService;
import com.yang.security.utils.UserHintUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Spring Security过滤器默认顺序
 * Creating filter chain: o.s.s.web.util.matcher.AnyRequestMatcher@1,
 * [o.s.s.web.context.SecurityContextPersistenceFilter@8851ce1,
 * o.s.s.web.header.HeaderWriterFilter@6a472566, o.s.s.web.csrf.CsrfFilter@61cd1c71,
 * o.s.s.web.authentication.logout.LogoutFilter@5e1d03d7,
 * o.s.s.web.authentication.UsernamePasswordAuthenticationFilter@122d6c22,
 * o.s.s.web.savedrequest.RequestCacheAwareFilter@5ef6fd7f,
 * o.s.s.web.servletapi.SecurityContextHolderAwareRequestFilter@4beaf6bd,
 * o.s.s.web.authentication.AnonymousAuthenticationFilter@6edcad64,
 * o.s.s.web.session.SessionManagementFilter@5e65afb6,
 * o.s.s.web.access.ExceptionTranslationFilter@5b9396d3,
 * o.s.s.web.access.intercept.FilterSecurityInterceptor@3c5dbdf8
 * ]
 *
 * @author jevon
 * @date 2018/10/09
 * @description WebSecurity配置
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private AuthenticationManager authenticationManager;

  @Bean
  public JwtAuthorizationTokenFilter getJwtAuthorizationTokenFilter() {

    RequestMatcher requestMatcher = new RequestMatcher() {
      @Override
      public boolean matches(HttpServletRequest request) {
        return false;
      }
    };

    JwtAuthorizationTokenFilter filter = new JwtAuthorizationTokenFilter(requestMatcher);
    filter.setAuthenticationManager(authenticationManager);
    return filter;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    // AuthenticationTokenFilter will ignore the below paths
    web
        .ignoring()
        .antMatchers(HttpMethod.GET, "/error")
        .antMatchers(HttpMethod.POST, "/error")
        .antMatchers(HttpMethod.POST, "/user/**")
        .and()
        .ignoring()
        .antMatchers(
            HttpMethod.GET,
            "/",
            "/*.html",
            "/favicon.ico",
            "/**/*.html",
            "/**/*.css",
            "/**/*.js")
        .and().ignoring().antMatchers(HttpMethod.GET, "/druid/**");
  }

  /**
   * @return UsernamePasswordAuthenticationFilter 重新加载自定义的该事例
   */
  @Bean
  public UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter() {
    UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
    usernamePasswordAuthenticationFilter.setFilterProcessesUrl("/user/login");
    usernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager);
    usernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(new LoginAuthenticationFailureHandler());
    usernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(new LoginAuthenticationSuccessHandler());
    return usernamePasswordAuthenticationFilter;
  }


  @Bean
  @Override
  protected UserDetailsService userDetailsService() {
    return new MyUserDetailsService();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        // we don't need CSRF because our token is invulnerable
        .csrf().disable()
        // don't create session
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/druid/**").permitAll()
        .antMatchers("/auth/**").permitAll()
        .antMatchers("/error").permitAll()
        .antMatchers("/test").hasRole("ADMIN")
        .anyRequest().authenticated();
    http.addFilterBefore(getJwtAuthorizationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
  }

  @Bean
  public FilterSecurityInterceptor getDynamicallyUrlInterceptor() {
    FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
    List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
    decisionVoters.add(new RoleVoter());
    interceptor.setSecurityMetadataSource(new MyFilterSecurityMetadataSource());
    interceptor.setAccessDecisionManager(new DynamicallyUrlAccessDecisionManager(decisionVoters));
    return interceptor;
  }

  @Bean
  public PasswordEncoder getPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    // 配置了DaoAuthenticationProvider中的userDetailsService和PasswordEncoder
    auth
        .userDetailsService(userDetailsService())
        .passwordEncoder(getPasswordEncoder());

    // 加入JwtAuthenticationProvider，用于处理JwtAuthentication
    auth.authenticationProvider(new JwtAuthenticationProvider());
  }

  /**
   * @return ExceptionTranslationFilter
   */
  @Bean
  public ExceptionTranslationFilter exceptionTranslationFilter() {
    AuthenticationEntryPoint authenticationEntryPoint = new AuthenticationEntryPoint() {
      @Override
      public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        UserHintUtil.userHintInformation(response, HttpServletResponse.SC_FORBIDDEN, authException.getMessage());
      }
    };

    AccessDeniedHandler accessDeniedHandler = new AccessDeniedHandler() {
      @Override
      public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        UserHintUtil.userHintInformation(response, HttpServletResponse.SC_UNAUTHORIZED, accessDeniedException.getMessage());
      }
    };

    ExceptionTranslationFilter exceptionTranslationFilter = new ExceptionTranslationFilter(authenticationEntryPoint);
    exceptionTranslationFilter.setAccessDeniedHandler(accessDeniedHandler);
    return exceptionTranslationFilter;
  }

}
