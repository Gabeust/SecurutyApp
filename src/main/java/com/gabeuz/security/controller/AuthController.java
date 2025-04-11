package com.gabeuz.security.controller;

import com.gabeuz.security.dto.AuthLoginRequestDTO;
import com.gabeuz.security.dto.AuthResponseDTO;
import com.gabeuz.security.dto.ChangePasswordRequest;
import com.gabeuz.security.dto.EmailRequestDTO;
import com.gabeuz.security.model.UserSec;
import com.gabeuz.security.service.EmailService;
import com.gabeuz.security.service.PasswordResetService;
import com.gabeuz.security.service.UserDetailsServiceImpl;
import com.gabeuz.security.service.UserSecService;
import com.gabeuz.security.util.JwtUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador REST para autenticación y operaciones relacionadas con la seguridad.
 *
 * Provee endpoints para login, logout, cambio y restablecimiento de contraseña.
 */

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserDetailsServiceImpl userDetailsService;
    private final PasswordResetService passwordResetService;
    private final EmailService emailService;
    private final JwtUtils jwtUtils;
    private final UserSecService userSecService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserDetailsServiceImpl userDetailsService, PasswordResetService passwordResetService, EmailService emailService, JwtUtils jwtUtils, UserSecService userSecService, PasswordEncoder passwordEncoder, UserSecService userSecService1, PasswordEncoder passwordEncoder1) {
        this.userDetailsService = userDetailsService;
        this.passwordResetService = passwordResetService;
        this.emailService = emailService;
        this.jwtUtils = jwtUtils;

        this.userSecService = userSecService1;
        this.passwordEncoder = passwordEncoder1;
    }
    /**
     * Autentica al usuario y genera un token JWT si las credenciales son válidas.
     *
     * @param loginRequestDTO contiene email y contraseña
     * @return Token JWT y datos del usuario autenticado
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponseDTO> login(@RequestBody AuthLoginRequestDTO loginRequestDTO) {
        return new ResponseEntity<>(this.userDetailsService.loginUser(loginRequestDTO), HttpStatus.OK);
    }
    /**
     * Invalida el token JWT del usuario (logout manual).
     *
     * @param token el token JWT del encabezado Authorization
     * @return Mensaje de éxito
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String token) {
        String jwt = token.replace("Bearer ", "");
        jwtUtils.invalidateToken(jwt);
        return ResponseEntity.ok("Logged out successfully.!");
    }
    /**
     * Solicita el restablecimiento de contraseña para el email dado.
     * Envia un enlace por correo con un token válido por 15 minutos.
     *
     * @param emailRequestDTO contiene el email del usuario
     * @return Mensaje indicando si se envió el enlace
     */
    @PostMapping("/password-reset-request")
    public ResponseEntity<String> requestPasswordReset(@RequestBody EmailRequestDTO emailRequestDTO) {
        String email = emailRequestDTO.email();
        try {
            String token = passwordResetService.createResetToken(email);
            String resetLink = "Http://localhost:8080/auth/passwordReset?token=" + token;
            // Enviar correo con el enlace
            emailService.sendEmail(email, "Reset Password",  "Use the following link to reset your password: " + resetLink);
            return ResponseEntity.ok("A password reset link has been sent to your email.");
        } catch (UsernameNotFoundException e) {
            return ResponseEntity.status(404).body("User with that email was not found.");
        }
    }
    /**
     * Restablece la contraseña de un usuario usando un token válido.
     *
     * @param token token de restablecimiento
     * @param newPassword nueva contraseña
     * @return Mensaje de confirmación o error
     */
    @PostMapping("/password-reset")
    public ResponseEntity<String> resetPassword(@RequestParam String token, @RequestBody String newPassword) {
        try {
            passwordResetService.resetPassword(token, newPassword);
            return ResponseEntity.ok("Password reset successfully.");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body("Invalid or expired token.");
        }
    }
    /**
     * Permite a un usuario autenticado cambiar su contraseña actual.
     *
     * @param request objeto con contraseña actual y nueva
     * @param authentication contexto de autenticación (obtenido automáticamente)
     * @return Mensaje indicando el resultado del cambio
     */
    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("You are not authenticated.");
        }
        // Obtener email del usuario autenticado

        String email = authentication.getName();

        // Buscar usuario en la base de datos
        UserSec userSec = userSecService.findUserByEmail(email);
        if (userSec == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        }
        // Verificar la contraseña actual
        if (!passwordEncoder.matches(request.currentPassword(), userSec.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect current password.");
        }
        // Actualizar la contraseña
        userSec.setPassword(passwordEncoder.encode(request.newPassword()));
        userSecService.save(userSec);

        return ResponseEntity.ok("Password changed successfully.");
    }

}
