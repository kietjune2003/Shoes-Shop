package com.ecomerce.ptit.repository;

import com.ecomerce.ptit.model.Orders;
import com.ecomerce.ptit.model.Voucher;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrderRepository extends JpaRepository<Orders, Long> {
    List<Orders> findAllByUser_Email(String user_email);
    Optional<Orders> findOrdersByUser_EmailAndId(String user_email, Long id);
    Long countOrdersByVoucher(Voucher voucher);
}
