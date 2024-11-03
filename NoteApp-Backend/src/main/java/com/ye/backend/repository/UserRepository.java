package com.ye.backend.repository;

import com.ye.backend.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUserName(String username);

    Boolean existsByUserName(String username);
    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
}
