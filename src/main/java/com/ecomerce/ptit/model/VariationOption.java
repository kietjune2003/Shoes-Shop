package com.ecomerce.ptit.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "variation_option")
public class VariationOption {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "variation_option_id")
    private Long id;

    @Column(name = "value")
    private String value;

    //Variation
    @ManyToOne(cascade = CascadeType.MERGE)
    @JoinColumn(name = "variation_id")
    private Variation variation;

    //Product Item
    @OneToMany(mappedBy = "variationOption", cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    private List<ProductConfiguration> productConfigurations = new ArrayList<>();
}
