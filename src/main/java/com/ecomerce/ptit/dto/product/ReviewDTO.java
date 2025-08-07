package com.ecomerce.ptit.dto.product;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class ReviewDTO {
    private Long id;
    private String comment;
    private Integer rating;
    private Date createdAt;
    private Date updatedAt;
    private UserReview user;
}
