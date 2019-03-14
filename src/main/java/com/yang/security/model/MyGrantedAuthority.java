package com.yang.security.model;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author jevon
 */
public class MyGrantedAuthority implements GrantedAuthority {

  private String role;

  public MyGrantedAuthority() {
  }

  public MyGrantedAuthority(String role) {
    this.role = role;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (obj instanceof MyGrantedAuthority) {
      return role.equals(((MyGrantedAuthority) obj).role);
    }

    return false;
  }

  @Override
  public int hashCode() {
    return this.role.hashCode();
  }

  @Override
  public String toString() {
    return this.role;
  }


  @Override
  public String getAuthority() {
    return role;
  }
}
