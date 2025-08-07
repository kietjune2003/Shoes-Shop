package com.ecomerce.ptit.dto.product;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ProductConfigurationDTO {
    private Long productItemId;
    private String variationName;
    private String variationOption;
}
