package com.ecomerce.ptit.dto.user;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserAddressDTO {
    private AddressDTO address;
    private boolean isDefault;
}
