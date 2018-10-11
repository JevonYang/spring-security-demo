package com.yang.security.config;

import com.auth0.jwt.algorithms.Algorithm;
import com.yang.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.ArrayList;
import java.util.List;

/**
 * @author jevon
 * @date 2018/10/09
 * @description WebSecurity配置
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

//    @Autowired
//    private JwtAuthorizationTokenFilter jwtAuthorizationTokenFilter;
//
//    @Autowired
//    private JwtAuthenticationProvider jwtAuthenticationProvider;
//
    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public JwtAuthorizationTokenFilter getJwtAuthorizationTokenFilter() {
        List<String> skipList = new ArrayList<>();
        skipList.add("/auth/.*");
        JwtAuthorizationTokenFilter filter = new JwtAuthorizationTokenFilter(new SkipUrlMatcher(skipList));
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public Algorithm getAlgorithm() {
        return Algorithm.HMAC256("hello");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // AuthenticationTokenFilter will ignore the below paths
        web
            .ignoring()
                .antMatchers(
                        HttpMethod.POST,
                        "/auth/**"
                )
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
                //.exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and()
                // don't create session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers("/druid/**").permitAll()
                .antMatchers("/auth/**").permitAll()
                .antMatchers("/test").hasRole("TELLER")
                .anyRequest().authenticated();
        http.addFilterBefore(getJwtAuthorizationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(getDynamicallyUrlInterceptor(), FilterSecurityInterceptor.class);
    }

    @Bean
    public FilterSecurityInterceptor getDynamicallyUrlInterceptor() {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        List<AccessDecisionVoter<?>> list = new ArrayList<>();
        interceptor.setSecurityMetadataSource(new MyFilterSecurityMetadataSource());
        list.add(new RoleVoter());
        interceptor.setAccessDecisionManager(new DynamicallyUrlAccessDecisionManager(list));
        return interceptor;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // 在这里可以自定义DaoAuthenticationProvider
        JwtAuthenticationProvider jwtAuthenticationProvider = new JwtAuthenticationProvider();
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(this.passwordEncoder);
        daoAuthenticationProvider.setUserDetailsService(this.userDetailsService);
        // jwtAuthenticationProvider.
        auth.authenticationProvider(daoAuthenticationProvider);
        auth.authenticationProvider(jwtAuthenticationProvider);
        // auth.userDetailsService(this.userDetailsService).passwordEncoder(this.passwordEncoder);
        // auth.authenticationProvider();

//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        auth.authenticationProvider(authenticationProvider).userDetailsService(userDetailsService()).passwordEncoder(getPasswordEncoder());
//            .inMemoryAuthentication()
//                .passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("USER");
    }

}
