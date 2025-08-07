package com.ecomerce.ptit.service;

import com.ecomerce.ptit.dto.cart.PaymentMethodResponse;
import com.ecomerce.ptit.model.PaymentMethod;

import java.security.Principal;
import java.util.List;

public interface PaymentMethodService {

    List<PaymentMethodResponse> getAllPaymentMethod(Principal principal);
    PaymentMethod getPaymentEntity(Long id);

}
