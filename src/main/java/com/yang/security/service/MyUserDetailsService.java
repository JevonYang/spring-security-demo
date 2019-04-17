package com.yang.security.service;

import com.yang.security.dao.UserMapper;
import com.yang.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * @author jevon
 */
@Component
public class MyUserDetailsService implements UserDetailsService {

  @Autowired
  private UserMapper userMapper;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userMapper.findUserByUsername(username);
    if (user != null) {
      return user;
    } else {
      throw new UsernameNotFoundException("错误！请确认用户名密码！");
    }
  }
}
