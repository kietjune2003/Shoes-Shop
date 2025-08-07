package com.ecomerce.ptit.repository;

import com.ecomerce.ptit.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Role findRoleByRole(String role);
}
