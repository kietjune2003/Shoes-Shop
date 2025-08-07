package com.ecomerce.ptit.repository;

import com.ecomerce.ptit.model.StatusOrder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface StatusOrderRepository extends JpaRepository<StatusOrder, Long> {
    Optional<StatusOrder> findStatusOrderByOrderStatusContaining(String orderStatus);
}
