package com.ecomerce.ptit.service;

import com.ecomerce.ptit.dto.voucher.VoucherCreateRequest;
import com.ecomerce.ptit.dto.voucher.VoucherResponse;
import com.ecomerce.ptit.model.Voucher;

import java.security.Principal;
import java.util.List;
import org.springframework.http.ResponseEntity;

public interface VoucherService {
    List<VoucherResponse> getAll();
    ResponseEntity<?> createVoucher(VoucherCreateRequest voucherCreateRequest);
    ResponseEntity<?> editVoucher(VoucherCreateRequest voucherCreateRequest,Long voucherID);
    ResponseEntity<?> deleteVoucher(Long voucherID);
    ResponseEntity<?> calculate(String voucherCode,Double totalAmount);
    ResponseEntity<?> getVoucherDetail(Long voucherID);
}
