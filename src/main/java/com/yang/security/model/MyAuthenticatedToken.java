package com.yang.security.model;

import lombok.*;

/**
 * @author jevon
 * @date 认证后获取的凭证
 */

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class MyAuthenticatedToken {

    private String accessToken;

    private String refreshToken;

    private String tokenType;

    private Long expiresIn;

}
