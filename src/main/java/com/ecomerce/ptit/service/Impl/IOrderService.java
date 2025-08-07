package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.exception.OrderException;
import com.ecomerce.ptit.model.Address;
import com.ecomerce.ptit.model.Orders;
import com.ecomerce.ptit.model.User;
import com.ecomerce.ptit.repository.CartItemRepository;
import com.ecomerce.ptit.repository.CartRepository;
import com.ecomerce.ptit.repository.OrderRepository;
import com.ecomerce.ptit.service.OrderService;
import com.ecomerce.ptit.service.ProductService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@AllArgsConstructor
public class IOrderService implements OrderService {

    private final CartRepository cartRepository;
    private final CartItemRepository cartItemRepository;
    private final ProductService productService;
    private final OrderRepository orderRepository;
    @Override
    public Orders createOrder(User user, Address address) throws OrderException {
        return null;
    }

    @Override
    public Orders findOrderById(Long orderId) throws OrderException {
        return null;
    }

    @Override
    public List<Orders> userOrderHistory(Long userId) {
        return null;
    }

    @Override
    public Orders placedOrder(Long orderId) throws OrderException {
        return null;
    }

    @Override
    public Orders confirmedOrder(Long orderId) throws OrderException {
        return null;
    }

    @Override
    public Orders shippedOrder(Long orderId) throws OrderException {
        return null;
    }

    @Override
    public Orders deliveredOrder(Long orderId) throws OrderException {
        return null;
    }

    @Override
    public Orders canceledOrder(Long orderId) throws OrderException {
        return null;
    }

}
