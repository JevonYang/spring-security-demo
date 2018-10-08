package com.yang.security.service;

import com.yang.security.dao.AuthorityMapper;
import com.yang.security.dao.RoleMapper;
import com.yang.security.dao.UserMapper;
import com.yang.security.model.Authority;
import com.yang.security.model.Role;
import com.yang.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private AuthorityMapper authorityMapper;

    @Autowired
    private RoleMapper roleMapper;

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User tempUser = userMapper.findOneByUsername(username);
        List<Role> roles = roleMapper.findRolesByUsername(username);
        List<Authority> authorities= authorityMapper.findAuthoritiesByRoles(roles);

        System.out.println("=======================================================");

        try{
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
            for (Role role: roles) {
                grantedAuthorities.add(new SimpleGrantedAuthority(role.getValue()));
            }
            for (Authority authority:authorities) {
                grantedAuthorities.add(new SimpleGrantedAuthority(authority.getValue()));
            }
            return new org.springframework.security.core.userdetails.User(tempUser.getUsername(), tempUser.getPassword(), grantedAuthorities);
        }catch (Exception e){
            throw  new UsernameNotFoundException("禁止！用户"+username+"不存在，请重新再尝试");
        }
    }
}
