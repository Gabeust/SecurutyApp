package com.gabeuz.security.dto;
/**
 * DTO para representar una solicitud que contiene únicamente un email.
 *
 * Usado en operaciones como el restablecimiento de contraseña, donde
 * el usuario debe enviar su correo electrónico para recibir un enlace o código.
 *
 * @param email correo electrónico del usuario
 */
public record EmailRequestDTO(String email) {
}
