package com.gabeuz.security.controller;

import com.gabeuz.security.model.Role;
import com.gabeuz.security.service.interf.IRoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Optional;

/**
 * Controlador REST para la gestión de roles.
 *
 * Ofrece endpoints para obtener todos los roles, obtener un rol por ID,
 * crear un nuevo rol y eliminar un rol existente.
 */

@RestController
@RequestMapping("/api/v1/roles")
public class RoleController {

    private final IRoleService roleService;

    public RoleController(IRoleService roleService) {
        this.roleService = roleService;
    }
    /**
     * Obtiene todos los roles disponibles en el sistema.
     *
     * @return ResponseEntity con la lista de roles
     */
    @GetMapping
    public ResponseEntity<List<Role>> getAllRoles(){
        return ResponseEntity.ok(roleService.findAll());
    }
    /**
     * Obtiene un rol específico por su ID.
     *
     * @param id identificador del rol
     * @return ResponseEntity con el rol encontrado o 404 si no existe
     */
    @GetMapping("/{id}")
    public ResponseEntity<Role> getRoleById(@PathVariable Long id) {
        Optional<Role> role = roleService.findById(id);
        return role.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
    /**
     * Crea un nuevo rol.
     *
     * @param role objeto Role recibido en el cuerpo de la petición
     * @return el rol creado
     */
    @PostMapping
    public Role createRole(@RequestBody Role role){
        return roleService.save(role);
    }

    /**
     * Elimina un rol por su ID.
     *
     * @param id identificador del rol a eliminar
     * @return ResponseEntity con mensaje de éxito o error si no se encuentra
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteById(@PathVariable long id){
        Optional<Role>  role = roleService.findById(id);
        if (role.isEmpty()){
            return ResponseEntity.status(404).body("Role not found.");
        } else {
            roleService.deleteById(id);
            return ResponseEntity.status(200).body("Role deleted successfully.") ;
        }
    }
}
