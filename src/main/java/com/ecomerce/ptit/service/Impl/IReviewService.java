package com.ecomerce.ptit.service.Impl;

import com.ecomerce.ptit.model.Review;
import com.ecomerce.ptit.repository.ReviewRepository;
import com.ecomerce.ptit.service.CloudinaryService;
import com.ecomerce.ptit.service.ReviewService;
import com.ecomerce.ptit.util.ByteMultipartFile;
import com.ecomerce.ptit.util.FileUtil;
import com.ecomerce.ptit.util.ImageUtil;
import lombok.RequiredArgsConstructor;
import org.apache.tika.Tika;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;


@Service
@RequiredArgsConstructor
public class IReviewService implements ReviewService {

    private final CloudinaryService cloudinaryService;
    private final ReviewRepository reviewRepository;
    @Override
    public String getURLPictureAndUploadToCloudinaryReview(String base64Content) {
        try {
            byte[] fileBytes = FileUtil.base64ToBytes(base64Content);
            MultipartFile multipartFile = new ByteMultipartFile(fileBytes);
            Tika tika = new Tika();
            String mimetype = tika.detect(fileBytes);
            if (mimetype.contains("image")) {
                Map<?, ?> map = cloudinaryService.uploadFile(multipartFile, "Review");
                return (String) map.get("secure_url");
            } else
                return ImageUtil.urlImage;
        } catch (Exception exception) {
            return null;
        }
    }

    @Override
    public List<Review> findAllByUser_Email(String user_email) {
        return reviewRepository.findAllByUser_Email(user_email);
    }

    @Override
    public Review findReviewByUser_EmailAndOrderItemId(String user_email, Long orderItemId) {
        return reviewRepository.findAllByOrderItem_IdAndUser_Email(orderItemId, user_email).orElseThrow();
    }

    @Override
    public List<Review> findAllByProductId(Long id) {
        return reviewRepository.findReviewsByProduct_Id(id);
    }
}
