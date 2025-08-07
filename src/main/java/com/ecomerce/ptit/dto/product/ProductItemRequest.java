package com.ecomerce.ptit.dto.product;

import lombok.Data;

@Data
public class ProductItemRequest {
    private Integer price;
    private Integer warehousePrice;
    private Integer warehouseQuantity;
    private Integer quantityInStock;
    private String productImage;
    private String size;
    private String color;
}
