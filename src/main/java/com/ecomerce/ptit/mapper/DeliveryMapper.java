package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.order.DeliveryDTO;
import com.ecomerce.ptit.model.Delivery;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface DeliveryMapper {

    DeliveryDTO toDeliveryResponse(Delivery delivery);
    List<DeliveryDTO> toDeliveryResponses(List<Delivery> deliveries);
}
