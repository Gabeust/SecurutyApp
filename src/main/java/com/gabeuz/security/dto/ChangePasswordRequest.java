package com.gabeuz.security.dto;
/**
 * DTO para el cambio de contraseña de un usuario autenticado.
 *
 * Se utiliza cuando el usuario desea actualizar su contraseña actual.
 *
 * @param currentPassword la contraseña actual del usuario (para verificación)
 * @param newPassword     la nueva contraseña que desea establecer
 */
public record ChangePasswordRequest(String currentPassword,  String newPassword) {
}
