package com.gabeuz.security.service;

import com.gabeuz.security.model.UserSec;
import com.gabeuz.security.repository.IUserRepository;
import com.gabeuz.security.service.interf.IUserSecService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserSecService implements IUserSecService {
    private final IUserRepository userRepository;

    public UserSecService(IUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public List<UserSec> findAll() {
        return userRepository.findAll();
    }

    @Override
    public Optional<UserSec> findbyId(Long id) {
        return userRepository.findById(id);
    }
    @Override
    public UserSec findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public UserSec save(UserSec userSec) {
        return userRepository.save(userSec);
    }

    @Override
    public void deleteById(Long id) {
    userRepository.deleteById(id);
    }

    @Override
    public String encriptPassword(String password) {
        return new BCryptPasswordEncoder().encode(password);
    }


}
