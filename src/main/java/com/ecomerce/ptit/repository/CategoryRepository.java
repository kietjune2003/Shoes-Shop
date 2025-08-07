package com.ecomerce.ptit.repository;

import com.ecomerce.ptit.model.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {
    List<Category> findAllByParentCategoryId_Id(Long parentCategoryId_id);
}
