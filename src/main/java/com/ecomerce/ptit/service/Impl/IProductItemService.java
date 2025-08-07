package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.model.ProductItem;
import com.ecomerce.ptit.repository.ProductItemRepository;
import com.ecomerce.ptit.service.ProductItemService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class IProductItemService implements ProductItemService {
    private final ProductItemRepository productItemRepository;
    @Override
    public List<?> getAllProductItem() {
        return productItemRepository.findAll();
    }

    @Override
    public ProductItem getProductItem(Long id) {
        return productItemRepository.findById(id).orElseThrow();
    }
}
