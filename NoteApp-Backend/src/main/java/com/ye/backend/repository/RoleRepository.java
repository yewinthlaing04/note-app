package com.ye.backend.repository;

import com.ye.backend.models.Role;
import com.ye.backend.models.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
