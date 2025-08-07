package com.ecomerce.ptit.dto.cart;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
public class PaymentMethodResponse {
    private Long id;
    private String nameMethod;
    private String describes;

}
