package com.ecomerce.ptit.dto.cartItem;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CartItemEditRequest {
    private Integer quantity;
    private Long productItemId;
}
