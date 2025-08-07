package com.ecomerce.ptit.dto.user;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserProfileResponse {
    private String email;
    private String firstName;
    private String lastName;
    private String phone;
    private boolean isEmailActive;
    private boolean isPhoneActive;
    private String avatar;
}
