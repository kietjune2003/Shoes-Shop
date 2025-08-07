package com.ecomerce.ptit.dto.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class UserResponse {
    private Long id;
    private String email;
    private boolean isEmailActive;
    private boolean isActive;
    private String phone;

}
