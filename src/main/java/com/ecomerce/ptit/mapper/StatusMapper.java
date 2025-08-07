package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.status.StatusOrderDTO;
import com.ecomerce.ptit.model.StatusOrder;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface StatusMapper {
    StatusOrderDTO toStatusOrderDTO(StatusOrder statusOrder);
    List<StatusOrderDTO> toStatusOrderDTOs(List<StatusOrder> statusOrders);
}
