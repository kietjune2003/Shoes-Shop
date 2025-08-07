package com.ecomerce.ptit.dto.order;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor

public class PaymentMethodDTO {
    private Long id;
    private String nameMethod;
    private Long paymentMethodId;
}
