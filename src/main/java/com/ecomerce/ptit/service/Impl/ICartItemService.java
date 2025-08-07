package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.mapper.CartMapper;
import com.ecomerce.ptit.model.CartItem;
import com.ecomerce.ptit.repository.CartItemRepository;
import com.ecomerce.ptit.repository.CartRepository;
import com.ecomerce.ptit.service.CartItemService;
import com.ecomerce.ptit.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ICartItemService implements CartItemService {

    private final CartItemRepository cartItemRepository;
    private final UserService userService;
    private final CartRepository cartRepository;
    private final CartMapper cartMapper;

    @Override
    public CartItem getCartItem(Long id) {
        var cartItem = cartItemRepository.findById(id);
        return cartItem.orElse(null);
    }
}
