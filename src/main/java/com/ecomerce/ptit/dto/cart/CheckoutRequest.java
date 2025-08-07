package com.ecomerce.ptit.dto.cart;

import lombok.*;

import java.util.List;

@Data
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CheckoutRequest {
    private List<Long> cartItemId;
    private UserAddressRequestv2 userAddressRequestv2;
    private Long paymentMethodId;
    private Long deliveryId;
    private Integer reducedPrice;
    private String voucherCode;
}
