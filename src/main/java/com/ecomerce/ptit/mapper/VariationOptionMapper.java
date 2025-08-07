package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.variationOption.VariationOptionResponse;
import com.ecomerce.ptit.model.VariationOption;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface VariationOptionMapper {
    VariationOptionResponse toVariationOptionResponse(VariationOption variationOption);
    List<VariationOptionResponse> toVariationOptionResponses(List<VariationOption> variationOptions);
}
