package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.model.UserPaymentMethod;
import com.ecomerce.ptit.repository.UserPaymentMethodRepository;
import com.ecomerce.ptit.service.UserPaymentMethodService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class IUserPaymentMethodService implements UserPaymentMethodService {
    private final UserPaymentMethodRepository userPaymentMethodRepository;
    @Override
    public List<UserPaymentMethod> getAllUserPaymentMethod(Long id) {
        return userPaymentMethodRepository.findAllByUser_Id(id);
    }
}
