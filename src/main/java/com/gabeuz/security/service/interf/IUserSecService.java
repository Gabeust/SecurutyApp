package com.gabeuz.security.service.interf;

import com.gabeuz.security.model.UserSec;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Optional;

public interface IUserSecService {
    List<UserSec> findAll();
    Optional<UserSec> findbyId(Long id);
    UserSec save (UserSec userSec);
    void deleteById(Long id);
    String encriptPassword(String password);
    UserSec findUserByEmail(String email);
    boolean existsByEmail(@NotBlank @Email String email);
}
