package com.ecomerce.ptit.dto.review;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ReviewRequest {
    private Long orderItemId;
    private Long productId;
    private Integer ratingStars;
    private String feedback;
    private String imageFeedback;
}
