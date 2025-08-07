package com.ecomerce.ptit.service;

import com.ecomerce.ptit.dto.status.StatusOrderDTO;

import java.util.List;

public interface StatusService {
    List<StatusOrderDTO> getAllStatusOrder();
}
