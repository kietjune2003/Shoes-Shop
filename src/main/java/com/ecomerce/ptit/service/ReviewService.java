package com.ecomerce.ptit.service;

import com.ecomerce.ptit.model.Review;

import java.util.List;

public interface ReviewService{
    String getURLPictureAndUploadToCloudinaryReview(String base64Content);
    List<Review> findAllByUser_Email(String user_email);
    Review findReviewByUser_EmailAndOrderItemId(String user_email, Long orderItemId);
    List<Review> findAllByProductId(Long id);

}
