package com.gabeuz.security.dto;

import jakarta.validation.constraints.NotBlank;
/**
 * DTO para manejar las solicitudes de autenticación (login).
 *
 * Contiene los datos que el usuario debe enviar para iniciar sesión: email y contraseña.
 *
 * Validaciones:
 * - Ambos campos son obligatorios (no deben estar en blanco).
 *
 * @param email    correo electrónico del usuario
 * @param password contraseña del usuario
 */
public record AuthLoginRequestDTO (@NotBlank String email, @NotBlank String password){
}
