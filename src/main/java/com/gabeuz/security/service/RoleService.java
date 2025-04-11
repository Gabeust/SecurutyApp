package com.gabeuz.security.service;

import com.gabeuz.security.model.Role;
import com.gabeuz.security.repository.IRoleRepository;
import com.gabeuz.security.service.interf.IRoleService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class RoleService implements IRoleService {

    private final IRoleRepository  roleRepository;

    public RoleService(IRoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public List<Role> findAll() {
        return roleRepository.findAll();
    }

    @Override
    public Optional<Role> findById(Long id) {
        return roleRepository.findById(id);
    }
    @Override
    public Role save(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void deleteById(Long id) {
    roleRepository.deleteById(id);
    }
}
