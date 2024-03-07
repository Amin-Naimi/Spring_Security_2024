package com.mohamed.security.dto.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationResponse {
 @JsonProperty("acccess_token")
    private String accessToken;
    private String refreshToken;

}
