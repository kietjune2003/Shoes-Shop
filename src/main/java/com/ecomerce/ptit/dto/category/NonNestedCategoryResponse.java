package com.ecomerce.ptit.dto.category;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class NonNestedCategoryResponse {
    private Long id;
    private String name;
    private Long parentCategoryId;
}
