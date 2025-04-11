package com.gabeuz.security.repository;

import com.gabeuz.security.model.UserSec;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IUserRepository extends JpaRepository <UserSec, Long>{

    UserSec findUserByEmail(String email);
    boolean existsByEmail(String email);

}
