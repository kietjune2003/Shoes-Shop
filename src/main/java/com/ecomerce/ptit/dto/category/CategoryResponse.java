package com.ecomerce.ptit.dto.category;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class CategoryResponse {
    private Long id;
    private String name;
    private Long parentCategoryId;
    private List<CategoryResponse> categories;

}
