package com.yang.security.config;

import com.yang.security.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new MyUserDetailsService();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(this.getDynamicallyUrlInterceptor(), FilterSecurityInterceptor.class);
//            .authorizeRequests()
//                .antMatchers("/", "/home").hasRole("ADMIN")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .and()
//                .logout()
//                .permitAll().and().addFilterBefore(this.getDynamicallyUrlInterceptor(), FilterSecurityInterceptor.class);
    }

    @Bean
    public FilterSecurityInterceptor getDynamicallyUrlInterceptor() {
        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        MyFilterSecurityMetadataSource metadataSource = new MyFilterSecurityMetadataSource();
        List<AccessDecisionVoter<?>> list = new ArrayList<>();
        interceptor.setSecurityMetadataSource(new MyFilterSecurityMetadataSource());
        list.add(new WebExpressionVoter());
        interceptor.setAccessDecisionManager(new AffirmativeBased(list));
        return interceptor;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService()).passwordEncoder(getPasswordEncoder());

//        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
//        auth.authenticationProvider(authenticationProvider).userDetailsService(userDetailsService()).passwordEncoder(getPasswordEncoder());
//            .inMemoryAuthentication()
//                .passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("admin").password(new BCryptPasswordEncoder().encode("123456")).roles("USER");
    }

}
