package com.ecomerce.ptit.service;

import com.ecomerce.ptit.dto.order.DeliveryDTO;
import com.ecomerce.ptit.model.Delivery;

import java.security.Principal;
import java.util.List;

public interface DeliveryService {
    List<DeliveryDTO> getAllDelivery(Principal principal);
    Delivery getDeliveryEntity(Long id);
}
