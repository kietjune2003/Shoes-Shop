package com.ecomerce.ptit.controller;


import com.ecomerce.ptit.dto.voucher.VoucherCreateRequest;
import com.ecomerce.ptit.service.VoucherService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/voucher")
@AllArgsConstructor
public class VoucherController {
    private final VoucherService voucherService;

    @PostMapping("/create")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> createVoucher(@RequestBody @Valid VoucherCreateRequest voucherCreateRequest){
        return voucherService.createVoucher(voucherCreateRequest);
    }
    @PutMapping("/edit/{voucherID}")
    public ResponseEntity<?> editVoucher(@RequestBody @Valid VoucherCreateRequest voucherCreateRequest,@PathVariable Long voucherID){
        return voucherService.editVoucher(voucherCreateRequest,voucherID);
    }
    @PostMapping("/delete/{voucherID}")
    public ResponseEntity<?> deleteVoucher(@PathVariable Long voucherID){
        return voucherService.deleteVoucher(voucherID);
    }
    @GetMapping("/calculate")
    public ResponseEntity<?> calculate(
            @RequestParam String voucherCode,
            @RequestParam Double totalAmount
    ){
        return voucherService.calculate(voucherCode,totalAmount);
    }
}
