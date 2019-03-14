package com.yang.security.dao;

import com.yang.security.model.User;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

/**
 * @author jevon
 */
@Repository
public interface UserMapper {

  /**
   * 通过用户名查找对应的Entity
   *
   * @param username 用户名
   * @return User 业务中用户的Entity
   */
  User findUserByUsername(@Param("username") String username);

}