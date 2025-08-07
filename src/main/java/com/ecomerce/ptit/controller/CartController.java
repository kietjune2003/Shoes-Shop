package com.ecomerce.ptit.controller;

import com.ecomerce.ptit.dto.cart.CheckoutRequest;
import com.ecomerce.ptit.dto.cartItem.CartItemEditRequest;
import com.ecomerce.ptit.service.CartService;
import com.ecomerce.ptit.service.DeliveryService;
import com.ecomerce.ptit.service.PaymentMethodService;
import com.ecomerce.ptit.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URISyntaxException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/cart")
@RequiredArgsConstructor
public class CartController {
    private final CartService cartService;
    private final UserService userService;
    private final DeliveryService deliveryService;
    private final PaymentMethodService paymentMethodService;

    @GetMapping("/")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getCart(Principal principal) {
        return cartService.getUserCart(principal);
    }

    @PostMapping("/")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> editCart(
            Principal principal,
            @RequestBody @Valid List<CartItemEditRequest> list
    ) {
        return cartService.editUserCart(principal, list);
    }

    @PostMapping("/checkout")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> checkout(Principal principal, @RequestBody @Valid CheckoutRequest list,
                                      HttpServletRequest request,
                                      RedirectAttributes redirectAttributes) throws URISyntaxException {
        return cartService.checkoutCart(principal, list, request, redirectAttributes);
    }

    @GetMapping("/delivery")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAllDelivery(Principal principal) {
        var deliveries = deliveryService.getAllDelivery(principal);
        return ResponseEntity.status(HttpStatus.OK).body(deliveries);
    }

    @GetMapping("/payment_method")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity<?> getAllPaymentMethod(Principal principal) {
        var paymentMethods = paymentMethodService.getAllPaymentMethod(principal);
        return ResponseEntity.status(HttpStatus.OK).body(paymentMethods);

    }



}
