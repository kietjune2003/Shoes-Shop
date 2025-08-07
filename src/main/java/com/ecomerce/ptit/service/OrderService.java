package com.ecomerce.ptit.service;

import com.ecomerce.ptit.exception.OrderException;
import com.ecomerce.ptit.model.Address;
import com.ecomerce.ptit.model.Orders;
import com.ecomerce.ptit.model.User;

import java.util.List;

public interface OrderService {
    Orders createOrder(User user, Address address) throws OrderException;
    Orders findOrderById(Long orderId) throws OrderException;
    List<Orders> userOrderHistory(Long userId);
    Orders placedOrder(Long orderId) throws OrderException;
    Orders confirmedOrder(Long orderId) throws OrderException;
    Orders shippedOrder(Long orderId) throws OrderException;
    Orders deliveredOrder(Long orderId) throws OrderException;
    Orders canceledOrder(Long orderId) throws OrderException;
}
