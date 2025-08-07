package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.cart.PaymentMethodResponse;
import com.ecomerce.ptit.model.PaymentMethod;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface PaymentMethodMapper {

    PaymentMethodResponse toPaymentMethodResponse(PaymentMethod paymentMethod);

    List<PaymentMethodResponse> toPaymentMethodResponses(List<PaymentMethod> paymentMethods);
}
