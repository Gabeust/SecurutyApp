package com.gabeuz.security.dto;

/**
 * DTO de respuesta para una solicitud de autenticación (login).
 *
 * Contiene los datos que se devuelven al usuario luego de autenticarse correctamente:
 * - El correo electrónico del usuario autenticado.
 * - Un mensaje descriptivo.
 * - El token JWT generado para la sesión.
 * - Un booleano indicando el estado del login (éxito o fallo).
 *
 * @param email   correo electrónico del usuario autenticado
 * @param message mensaje descriptivo sobre el resultado del login
 * @param jwt     token JWT generado para el usuario
 * @param status  indica si la autenticación fue exitosa (true) o fallida (false)
 */
public record AuthResponseDTO (String email, String message, String jwt, boolean status){
}
