package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.dto.cart.PaymentMethodResponse;
import com.ecomerce.ptit.mapper.PaymentMethodMapper;
import com.ecomerce.ptit.model.PaymentMethod;
import com.ecomerce.ptit.repository.PaymentMethodRepository;
import com.ecomerce.ptit.service.PaymentMethodService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.List;

@Service
@RequiredArgsConstructor
public class IPaymentMethodService implements PaymentMethodService {
    private final PaymentMethodRepository paymentMethodRepository;
    private final PaymentMethodMapper paymentMethodMapper;
    @Override
    public List<PaymentMethodResponse> getAllPaymentMethod(Principal principal) {
        var paymentMethods = paymentMethodRepository.findAll();
        return paymentMethodMapper.toPaymentMethodResponses(paymentMethods);
    }

    @Override
    public PaymentMethod getPaymentEntity(Long id) {
        var paymentMethodEntity = paymentMethodRepository.findById(id);
        return paymentMethodEntity.orElse(null);
    }

}
