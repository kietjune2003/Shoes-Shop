package com.ecomerce.ptit.service;

import com.ecomerce.ptit.model.ProductItem;

import java.util.List;

public interface ProductItemService {
    List<?> getAllProductItem();
    ProductItem getProductItem(Long id);
}
