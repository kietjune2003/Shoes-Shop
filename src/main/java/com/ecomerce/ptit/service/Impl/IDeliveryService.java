package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.dto.order.DeliveryDTO;
import com.ecomerce.ptit.mapper.DeliveryMapper;
import com.ecomerce.ptit.model.Delivery;
import com.ecomerce.ptit.repository.DeliveryRepository;
import com.ecomerce.ptit.service.DeliveryService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.util.List;

@Service
@RequiredArgsConstructor
public class IDeliveryService implements DeliveryService {
    private final DeliveryRepository deliveryRepository;
    private final DeliveryMapper deliveryMapper;
    @Override
    public List<DeliveryDTO> getAllDelivery(Principal principal) {
        var deliveries = deliveryRepository.findAll();
        return deliveryMapper.toDeliveryResponses(deliveries);
    }

    @Override
    public Delivery getDeliveryEntity(Long id) {
        var delivery = deliveryRepository.findById(id);
        return delivery.orElse(null);
    }
}
