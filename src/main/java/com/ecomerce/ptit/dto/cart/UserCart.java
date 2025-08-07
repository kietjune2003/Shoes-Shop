package com.ecomerce.ptit.dto.cart;

import com.ecomerce.ptit.dto.cartItem.CartItemDTO;
import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class UserCart {
    private Long id;
    private Long userId;
    private Integer totalPrice;
    private int totalItem;
    private List<CartItemDTO> cartItems;

}
