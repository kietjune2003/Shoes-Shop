package com.ecomerce.ptit.repository;

import com.ecomerce.ptit.model.Variation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface VariationRepository extends JpaRepository<Variation, Long> {
    List<Variation> findVariationsByCategory_Id(Long category_id);
    Variation findVariationByCategory_IdAndNameContaining(Long category_id, String name);
}
