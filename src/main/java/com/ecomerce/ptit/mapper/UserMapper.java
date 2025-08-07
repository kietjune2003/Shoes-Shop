package com.ecomerce.ptit.mapper;

import com.ecomerce.ptit.dto.user.*;
import com.ecomerce.ptit.model.*;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserProfileResponse toUserProfileResponse(User user);

    @Mapping(source = "emailActive", target = "emailActive")
    @Mapping(source = "phoneActive", target = "phoneActive")
    @Mapping(source = "active", target = "active")
    UserDetailResponse toUserDetailResponse(User user);
    UserResponse toUserResponse(User user);
    List<UserResponse> toListUserResponse(List<User> userList);

    @Mapping(source = "default", target = "default")
    UserAddressResponse toUserAddressResponse(UserAddress userAddress);
    List<UserAddressResponse> toListUserAddressResponse(List<UserAddress> userAddresses);
    AddressDTO toUserAddressDTO(Address address);

    Address toAddressEntity(UserAddressRequest userAddressRequest);
}
