package com.yang.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * @author jevon
 * @date 认证后获取的凭证
 */

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class LoginSuccessInfo {

  @JsonProperty(value = "access_token")
  private String accessToken;

  @JsonProperty(value = "refresh_token")
  private String refreshToken;

  @JsonProperty(value = "token_type")
  private String tokenType;

  @JsonProperty(value = "expires_in")
  private Long expiresIn;
}
