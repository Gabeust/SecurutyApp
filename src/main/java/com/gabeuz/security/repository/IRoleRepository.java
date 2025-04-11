package com.gabeuz.security.repository;

import com.gabeuz.security.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IRoleRepository extends JpaRepository<Role, Long> {
}
