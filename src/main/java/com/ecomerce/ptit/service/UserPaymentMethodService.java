package com.ecomerce.ptit.service;

import com.ecomerce.ptit.model.UserPaymentMethod;

import java.util.List;

public interface UserPaymentMethodService {
    List<UserPaymentMethod> getAllUserPaymentMethod(Long userId);
}
