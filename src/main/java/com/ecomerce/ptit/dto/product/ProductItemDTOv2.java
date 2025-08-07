package com.ecomerce.ptit.dto.product;

import lombok.*;

@Setter
@Getter
public class ProductItemDTOv2 {
    private Long id;
    private Integer price;
    private Integer warehousePrice;
    private Integer warehouseQuantity;
    private Integer quantityInStock;
    private String productImage;
    private boolean active;
    private String size;
    private String color;
}
