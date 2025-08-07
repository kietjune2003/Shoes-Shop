package com.ecomerce.ptit.dto.product;

import lombok.*;

@Setter
@Getter
@NoArgsConstructor
public class ProductItemCartDTO {
    private Long id;
    private String productImage;
    private String name;
}
