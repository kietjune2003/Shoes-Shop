package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.dto.status.StatusOrderDTO;
import com.ecomerce.ptit.mapper.StatusMapper;
import com.ecomerce.ptit.repository.StatusOrderRepository;
import com.ecomerce.ptit.service.StatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class IStatusService implements StatusService {
    private final StatusOrderRepository statusOrderRepository;
    private final StatusMapper statusMapper;
    @Override
    public List<StatusOrderDTO> getAllStatusOrder() {
        return  statusMapper.toStatusOrderDTOs(statusOrderRepository.findAll());
    }
}
