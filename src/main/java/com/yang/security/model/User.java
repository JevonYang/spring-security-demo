package com.yang.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;


/**
 * @author jevon
 * @date 2018/10/09
 */

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class User implements UserDetails {
    /** id*/
    private Long id;

    /** 用户名*/
    private String username;

    /** 密码*/
    private String password;

    /** 公司*/
    private String company;

    /** 部门*/
    private String department;

    /** 创建者*/
    private String createBy;

    /** 创建时间*/
    private Date createDate;

    private Set<GrantedAuthority> authorities;

    public User(Long id, String username, String company, String department, Set<GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.company = company;
        this.department = department;
        this.authorities = authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setAuthorities(Set<GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @Override
    public Set<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public String[] getAuthoritiesToString() {
        List<String> list = new ArrayList<>();
        for (GrantedAuthority authority: authorities) {
            list.add(authority.getAuthority());
        }
        String[] strings = new String[list.size()];
        return list.toArray(strings);
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}