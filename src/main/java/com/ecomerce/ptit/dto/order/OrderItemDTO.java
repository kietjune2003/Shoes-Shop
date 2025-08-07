package com.ecomerce.ptit.dto.order;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
public class OrderItemDTO {
    private Long id;
    private Integer quantity;
    private Integer price;
    private Integer totalPrice;
    private Long productItemId;
    private Long productId;
    private String productItemName;
    private String productItemImage;
    private String size;
    private String color;
}
