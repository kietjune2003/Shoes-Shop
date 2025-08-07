package com.ecomerce.ptit.dto.user;

import com.ecomerce.ptit.dto.product.ProductDTO;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class UserReviewDTO {
    private Long id;
    private String comment;
    private Double rating;
    private Date createdAt;
    private Date updatedAt;
    private ProductDTO product;

}
