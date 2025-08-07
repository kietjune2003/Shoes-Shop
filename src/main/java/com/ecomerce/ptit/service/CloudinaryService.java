package com.ecomerce.ptit.service;

import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

public interface CloudinaryService {
    Map<?, ?> uploadFile(MultipartFile file, String folderName);

}
