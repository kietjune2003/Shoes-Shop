package com.ecomerce.ptit.dto.cart;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserAddressRequestv2 {
    private String city;
    private String district;
    private String ward;
    private String address;
}
