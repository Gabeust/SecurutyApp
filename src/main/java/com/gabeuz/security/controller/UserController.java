package com.gabeuz.security.controller;

import com.gabeuz.security.model.Role;
import com.gabeuz.security.model.UserSec;
import com.gabeuz.security.service.interf.IRoleService;
import com.gabeuz.security.service.interf.IUserSecService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * Controlador REST para operaciones sobre usuarios del sistema.
 *
 * Provee endpoints para listar todos los usuarios, obtener uno por ID y crear un nuevo usuario.
 */

@RestController
@RequestMapping("/api/v1/usuarios")
public class UserController {

    private final IUserSecService userSecService;
    private final IRoleService roleService;

    public UserController(IUserSecService userSecService, IRoleService roleService) {
        this.userSecService = userSecService;
        this.roleService = roleService;
    }

    /**
     * Obtiene todos los usuarios registrados en el sistema.
     *
     * @return lista de usuarios
     */
    @GetMapping
    public ResponseEntity<List<UserSec>>getAllUsers(){
        return ResponseEntity.ok(userSecService.findAll());
    }
    /**
     * Busca un usuario por su ID.
     *
     * @param id identificador del usuario
     * @return el usuario si existe, o 404 si no se encuentra
     */
    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        Optional<UserSec> user = userSecService.findbyId(id);
        if (user.isPresent()) {
            return ResponseEntity.ok(user.get());
        } else {
            return ResponseEntity.status(404).body("User not found");
        }
    }
    /**
     * Crea un nuevo usuario con roles asignados.
     *
     * Valida que el email no esté en uso, la contraseña no esté vacía y los roles existan.
     *
     * @param userSec objeto usuario a crear
     * @return usuario creado sin exponer contraseña
     */
    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody UserSec userSec) {
        // Valida si el email ya está en uso
        if (userSecService.existsByEmail(userSec.getEmail())) {
            return ResponseEntity.badRequest().body("Email is already registered.");
        }

        // Valida que la contraseña no esté vacía
        if (userSec.getPassword() == null || userSec.getPassword().isBlank()) {
            return ResponseEntity.badRequest().body("Password cannot be empty.");
        }

        // Encripta contraseña
        userSec.setPassword(userSecService.encriptPassword(userSec.getPassword()));

        // Verificar y asigna roles válidos
        Set<Role> roleList = new HashSet<>();
        for (Role role : userSec.getRolesList()) {
            roleService.findById(role.getId()).ifPresent(roleList::add);
        }

        if (roleList.isEmpty()) {
            return ResponseEntity.badRequest().body("The user must have at least one valid role.");
        }

        userSec.setRolesList(roleList);

        // Guardar usuario
        UserSec newUser = userSecService.save(userSec);

        // Retornar una respuesta segura sin exponer la contraseña
        return ResponseEntity.ok(Map.of(
                "id", newUser.getId(),
                "email", newUser.getEmail(),
                "roles", newUser.getRolesList().stream().map(Role::getName).toList(),
                "message", "User created successfully."
        ));
    }

}
