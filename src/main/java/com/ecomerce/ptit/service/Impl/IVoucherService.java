package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.dto.ApiResponse;
import com.ecomerce.ptit.dto.user.UserCreateRequest;
import com.ecomerce.ptit.dto.voucher.VoucherCreateRequest;
import com.ecomerce.ptit.dto.voucher.VoucherResponse;
import com.ecomerce.ptit.dto.voucher.VoucherResponseV2;
import com.ecomerce.ptit.model.*;
import com.ecomerce.ptit.repository.OrderRepository;
import com.ecomerce.ptit.repository.ProductRepository;
import com.ecomerce.ptit.repository.UserRepository;
import com.ecomerce.ptit.repository.VoucherRepository;
import com.ecomerce.ptit.service.VoucherService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import static com.ecomerce.ptit.constants.ErrorMessage.*;

@Service
@AllArgsConstructor
public class IVoucherService implements VoucherService {
    private final VoucherRepository voucherRepository;
    private final OrderRepository orderRepository;
    private final UserRepository userRepository;
    private final ProductRepository productRepository;

    @Override
    public List<VoucherResponse> getAll() {
        List<Voucher> vouchers = voucherRepository.findAll();
        List<VoucherResponse> voucherResponses =new ArrayList<>();
        for(Voucher voucher : vouchers){
            Long sumUsed = orderRepository.countOrdersByVoucher(voucher);
            VoucherResponse voucherResponse = VoucherResponse.builder()
                    .id(voucher.getId())
                    .name(voucher.getName())
                    .code(voucher.getCode())
                    .discount(voucher.getDiscount())
                    .minOder(voucher.getMinOder())
                    .begin(voucher.getBegin())
                    .end(voucher.getEnd())
                    .used(sumUsed)
                    .active(voucher.isActive())
                    .build();
            voucherResponses.add(voucherResponse);
        }
        return voucherResponses;
    }

    @Override
    public ResponseEntity<?> createVoucher(@Valid VoucherCreateRequest voucherCreateRequest) {
        var existedVoucher = voucherRepository.findByCode(voucherCreateRequest.getCode());
        if (existedVoucher.isPresent())
            return ResponseEntity.status(HttpStatus.CONFLICT).body(VOUCHER_IN_USE);
        Voucher voucher = Voucher.builder()
                .name(voucherCreateRequest.getName())
                .code(voucherCreateRequest.getCode())
                .maxUse(voucherCreateRequest.getMaxUse())
                .minOder(voucherCreateRequest.getMinOder())
                .userUse(voucherCreateRequest.getUserUse())
                .discount(voucherCreateRequest.getDiscount())
                .type(voucherCreateRequest.getType())
                .begin(voucherCreateRequest.getBegin())
                .end(voucherCreateRequest.getEnd())
                .active(true)
                .build();
        voucherRepository.save(voucher);
        return ResponseEntity.ok(ApiResponse.builder()
                .statusCode(200)
                .message("Created voucher successfully")
                .description("Successfully")
                .timestamp(new Date(System.currentTimeMillis()))
                .build());

    }
    @Override
    public ResponseEntity<?> editVoucher(@Valid VoucherCreateRequest voucherCreateRequest, Long voucherID) {
        var voucher = voucherRepository.findById(voucherID).get();
        if (!voucher.getCode().equals(voucherCreateRequest.getCode())) {
            var existedVoucher = voucherRepository.findByCode(voucherCreateRequest.getCode());
            if(existedVoucher.isPresent()) return ResponseEntity.status(HttpStatus.CONFLICT).body(VOUCHER_IN_USE);
        }
        var products = new HashSet<Product>();
        voucher.setName(voucherCreateRequest.getName());
        voucher.setCode(voucherCreateRequest.getCode());
        voucher.setMaxUse(voucherCreateRequest.getMaxUse());
        voucher.setMinOder(voucherCreateRequest.getMinOder());
        voucher.setUserUse(voucherCreateRequest.getUserUse());
        voucher.setDiscount(voucherCreateRequest.getDiscount());
        voucher.setType(voucherCreateRequest.getType());
        voucher.setBegin(voucherCreateRequest.getBegin());
        voucher.setEnd(voucherCreateRequest.getEnd());
        voucher.setActive(voucherCreateRequest.isActive());
        voucherRepository.save(voucher);
        return ResponseEntity.ok(ApiResponse.builder()
                .statusCode(200)
                .message("Update voucher successfully")
                .description("Successfully")
                .timestamp(new Date(System.currentTimeMillis()))
                .build());
    }
    @Override
    public ResponseEntity<?> deleteVoucher(@Valid Long voucherID){
        var existedVoucher = voucherRepository.findById(voucherID);
        if (!existedVoucher.isPresent())
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(VOUCHER_NOT_FOUND);
        var voucher = existedVoucher.get();
        voucher.setActive(false);
        voucherRepository.save(voucher);
        return ResponseEntity.ok(ApiResponse.builder()
                .statusCode(200)
                .message("Delete voucher successfully")
                .description("Successfully")
                .timestamp(new Date(System.currentTimeMillis()))
                .build());
    }

    @Override
    public ResponseEntity<?> calculate(String voucherCode, Double totalAmount) {
        var existedVoucher = voucherRepository.findByCode(voucherCode);
        System.out.println(existedVoucher.isPresent());
        if(!existedVoucher.isPresent()) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Voucher not found");
        var voucher = existedVoucher.get();
        if(totalAmount < voucher.getMinOder()){
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("min");
        }
        Date now = new Date();
        if(now.compareTo(voucher.getBegin()) < 0) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("ngoai thoi gian");
        if(voucher.getUserUse() == voucher.getMaxUse()) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Het luot dung");
        Double newTotal;
        if(voucher.getType() == 0){
            newTotal = totalAmount - Double.parseDouble(voucher.getDiscount());
        }
        else{
            String discount = "0." + voucher.getDiscount();
            newTotal = totalAmount*(1-Double.parseDouble(discount));
        }
        return ResponseEntity.status(HttpStatus.OK).body(newTotal);
    }
    @Override
    public ResponseEntity<?> getVoucherDetail(Long voucherID){
        Voucher voucher = voucherRepository.findById(voucherID).get();
        VoucherResponseV2 voucherResponse = VoucherResponseV2.builder()
                .id(voucher.getId())
                .name(voucher.getName())
                .code(voucher.getCode())
                .type(voucher.getType())
                .minOder(voucher.getMinOder())
                .maxUse(voucher.getMaxUse())
                .userUse(voucher.getUserUse())
                .discount(voucher.getDiscount())
                .begin(voucher.getBegin())
                .end(voucher.getEnd())
                .active(voucher.isActive())
                .build();
        return ResponseEntity.status(HttpStatus.OK).body(voucherResponse);
    }
}
