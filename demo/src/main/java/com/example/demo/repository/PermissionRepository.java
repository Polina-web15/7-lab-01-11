package com.example.demo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.model.Permission;

@Repository
public interface PermissionRepository extends JpaRepository <Permission, Long> {
    Optional <Permission> findByResourceAndOperation (String resource, String operation);
}
