package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.cart.UserCart;
import com.ecomerce.ptit.dto.cartItem.CartItemDTO;
import com.ecomerce.ptit.dto.product.ProductItemCartDTO;
import com.ecomerce.ptit.model.Cart;
import com.ecomerce.ptit.model.CartItem;
import com.ecomerce.ptit.model.ProductItem;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring")
public interface CartMapper {

    @Mapping(source = "user.id", target = "userId")
    UserCart toUserCart(Cart cart);
    CartItemDTO toCartItemDTO (CartItem cartItem);
    List<CartItemDTO> toCartItemDTOs(List<CartItem> cartItems);

    ProductItemCartDTO toProductItemCartDTO(ProductItem productItem);

}
