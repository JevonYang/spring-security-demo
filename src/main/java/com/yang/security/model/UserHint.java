package com.yang.security.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * 返回给用户的提示信息
 * @author jevon
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
@ToString
public class UserHint {
  private String message;
}
