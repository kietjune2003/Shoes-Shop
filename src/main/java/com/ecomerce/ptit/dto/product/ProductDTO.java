package com.ecomerce.ptit.dto.product;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProductDTO {
    private Long id;
    private String name;
    private String description;
    private String productImage;
    private Long categoryId;
    private boolean active;
}
