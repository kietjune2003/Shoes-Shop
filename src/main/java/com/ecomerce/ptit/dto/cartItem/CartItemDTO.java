package com.ecomerce.ptit.dto.cartItem;

import com.ecomerce.ptit.dto.product.ProductItemCartDTO;
import lombok.*;

@Setter
@Getter
@NoArgsConstructor
public class CartItemDTO {
    private Long id;
    private Integer quantity;
    private Integer price;
    private Integer totalPrice;
    private ProductItemCartDTO productItem;
}
