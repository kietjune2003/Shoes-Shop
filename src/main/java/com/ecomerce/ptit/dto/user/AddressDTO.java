package com.ecomerce.ptit.dto.user;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AddressDTO {
    private Long id;
    private String city;
    private String district;
    private String ward;
    private String address;
}
