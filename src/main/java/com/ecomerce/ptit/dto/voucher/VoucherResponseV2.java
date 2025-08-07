package com.ecomerce.ptit.dto.voucher;


import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
@Builder
public class VoucherResponseV2 {
    private Long id;
    private String code;

    private String name;

    private int type;

    private String discount;

    private Long minOder;

    private Long maxUse;

    private Long userUse;
    @Column(name = "begin")
    @DateTimeFormat(pattern = "dd/MM/yyyy HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private Date begin;

    @DateTimeFormat(pattern = "dd/MM/yyyy HH:mm:ss")
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    @Column(name = "end")
    private Date end;

    @Column(name = "active",columnDefinition = "True")
    private boolean active;

}
