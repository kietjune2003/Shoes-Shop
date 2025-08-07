package com.ecomerce.ptit.controller;

import com.ecomerce.ptit.dto.user.UserCreateRequest;
import com.ecomerce.ptit.dto.voucher.VoucherCreateRequest;
import com.ecomerce.ptit.exception.ErrorResponse;
import com.ecomerce.ptit.exception.InputFieldException;
import com.ecomerce.ptit.exception.UserException;
import com.ecomerce.ptit.service.*;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.repository.query.Param;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Date;

import static com.ecomerce.ptit.constants.ErrorMessage.EMAIL_NOT_FOUND;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Slf4j // 👉 Cho phép sử dụng log.info/debug/warn/error
public class AdminController {

    // Các service được inject qua constructor (Lombok @RequiredArgsConstructor)
    private final UserService userService;
    private final ProductService productService;
    private final StatusService statusService;
    private final OrderService orderService;
    private final VoucherService voucherService;

    // ✅ Lấy chi tiết 1 user theo id
    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getDetailUser(@RequestParam("id") Long id) throws UserException {
        log.info("Admin yêu cầu chi tiết user có id: {}", id);
        var user = userService.getDetailUser(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.status(HttpStatusCode.valueOf(404)).body(ErrorResponse.builder()
                    .statusCode(404)
                    .message(String.valueOf(HttpStatus.NOT_FOUND))
                    .description(EMAIL_NOT_FOUND)
                    .timestamp(new Date())
                    .build());
        }
    }

    // ✅ Tạo user mới
    @PostMapping("/users")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> createUser(Principal principal, @RequestBody @Valid UserCreateRequest userCreateRequest, BindingResult bindingResult) {
        log.info("Admin {} tạo user mới: {}", principal.getName(), userCreateRequest.getEmail());
        if (bindingResult.hasErrors()) {
            log.warn("Tạo user thất bại do lỗi dữ liệu đầu vào");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new InputFieldException(bindingResult).getMessage());
        }
        return userService.createUser(principal, userCreateRequest);
    }

    // ✅ Lấy danh sách tất cả user
    @GetMapping("/users")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getListUser() {
        log.info("Admin yêu cầu danh sách tất cả user");
        var list = userService.getAllUsers();
        return ResponseEntity.ok(list);
    }

    // ✅ Kích hoạt / vô hiệu hoá user
    @PostMapping("/users/active")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> deActiveOrActiveUser(Principal connectedUser, @RequestParam("id") Long id) {
        log.info("Admin {} thay đổi trạng thái user id: {}", connectedUser.getName(), id);
        return userService.deActiveOrActiveUser(connectedUser, id);
    }

    // ✅ Lấy tất cả sản phẩm
    @GetMapping("/products")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAllProduct() {
        log.info("Admin yêu cầu danh sách tất cả sản phẩm");
        var product = productService.getAllProductV2();
        if (product != null) {
            return ResponseEntity.ok(product);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Not found any shoes!");
        }
    }

    // ✅ Lấy chi tiết sản phẩm theo id
    @GetMapping("/products/{id}")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getDetailProduct(@PathVariable("id") Long id) {
        log.info("Admin yêu cầu chi tiết sản phẩm id: {}", id);
        var product = productService.getDetailProductForAdmin(id);
        if (product != null) {
            return ResponseEntity.ok(product);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Not found any shoes!");
        }
    }

    // ✅ Lấy tất cả đơn hàng của người dùng (admin quyền truy cập)
    @GetMapping("/orders")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAllOrders(Principal connectedUser) {
        log.info("Admin {} yêu cầu danh sách đơn hàng", connectedUser.getName());
        var userOrders = userService.getAllUserHistoryOrdersForAdmin(connectedUser);
        if (userOrders != null) {
            return ResponseEntity.ok(userOrders);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Lấy chi tiết đơn hàng
    @GetMapping("/orders/{id}")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getDetailOrder(Principal connectedUser, @PathVariable("id") Long id) {
        log.info("Admin {} xem chi tiết đơn hàng id: {}", connectedUser.getName(), id);
        var userOrders = userService.getUserHistoryOrderForAdmin(connectedUser, id);
        if (userOrders != null) {
            return ResponseEntity.ok(userOrders);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Thay đổi trạng thái đơn hàng
    @PostMapping("/orders/{id}")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> changeStatusOrderByAdmin(Principal connectedUser, @PathVariable("id") Long orderId, @Param("status") String status) {
        log.info("Admin {} thay đổi trạng thái đơn hàng id {} -> {}", connectedUser.getName(), orderId, status);
        var userOrders = userService.changeStatusOrderByAdmin(connectedUser, orderId, status);
        if (userOrders != null) {
            return ResponseEntity.ok(userOrders);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Lấy danh sách tất cả trạng thái đơn hàng
    @GetMapping("/orders/status")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAllStatus() {
        log.info("Admin yêu cầu danh sách trạng thái đơn hàng");
        var statusOrders = statusService.getAllStatusOrder();
        if (statusOrders != null) {
            return ResponseEntity.ok(statusOrders);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Lấy tổng doanh thu
    @GetMapping("/revenue")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getRevenue() {
        log.info("Admin yêu cầu thống kê doanh thu");
        var revenue = productService.getAllRevenue();
        if (revenue != null) {
            return ResponseEntity.ok(revenue);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Lấy danh sách voucher
    @GetMapping("/vouchers")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAll() {
        log.info("Admin yêu cầu danh sách voucher");
        var vouchers = voucherService.getAll();
        if (vouchers != null) {
            return ResponseEntity.ok(vouchers);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You do not have permission to access this resource!");
        }
    }

    // ✅ Lấy chi tiết voucher
    @GetMapping("/vouchers/{voucherID}")
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> voucherDetail(@PathVariable Long voucherID) {
        log.info("Admin yêu cầu chi tiết voucher id: {}", voucherID);
        return voucherService.getVoucherDetail(voucherID);
    }
}
