package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.category.NonNestedCategoryResponse;
import com.ecomerce.ptit.dto.category.CategoryResponse;
import com.ecomerce.ptit.model.Category;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring")
public interface CategoryMapper {

    @Mapping(source = "parentCategoryId.id", target = "parentCategoryId")
    CategoryResponse toCategoryResponse(Category category);
    List<CategoryResponse> toCategoryResponses(List<Category> categories);
    @Mapping(source = "parentCategoryId.id", target = "parentCategoryId")
    NonNestedCategoryResponse toNonNestedCategoryResponse(Category category);
    List<NonNestedCategoryResponse> toNonNestedCategoryResponses(List<Category> categories);

}
