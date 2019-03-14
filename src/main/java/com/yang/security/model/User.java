package com.yang.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.Set;


/**
 * @author jevon
 * @date 2018/10/09
 */

@Getter
@Setter
@ToString
@NoArgsConstructor
public class User implements UserDetails {

  /**
   * id
   */
  private Long id;

  /**
   * 用户名
   */
  private String username;

  /**
   * 密码
   */
  private String password;

  /**
   * 公司
   */
  private String company;

  /**
   * 部门
   */
  private String department;

  /**
   * 创建者
   */
  @JsonIgnore
  private String createBy;

  /**
   * 创建时间
   */
  @JsonIgnore
  private Date createDate;

  private Set<GrantedAuthority> authorities;

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

  public User(Long id, String username, String password, String company, String department, String createBy, Date createDate, Set<GrantedAuthority> authorities) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.company = company;
    this.department = department;
    this.createBy = createBy;
    this.createDate = createDate;
    this.authorities = authorities;
  }

  @Override
  public Set<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  public String[] getAuthorityList() {
    return authorities.stream().map(GrantedAuthority::getAuthority).toArray(String[]::new);
  }

  @Override
  @JsonIgnore
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  @JsonIgnore
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  @JsonIgnore
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  @JsonIgnore
  public boolean isEnabled() {
    return true;
  }
}