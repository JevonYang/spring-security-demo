package com.yang.security.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

/**
 * @author jevon
 * @date 2018/10/09
 */

@Getter
@Setter
public class LoginEntity {
    private String username;
    private String password;
}
