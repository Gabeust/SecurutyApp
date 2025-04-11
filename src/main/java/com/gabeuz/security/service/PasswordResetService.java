package com.gabeuz.security.service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.gabeuz.security.model.UserSec;
import com.gabeuz.security.repository.IUserRepository;
import com.gabeuz.security.util.JwtUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

/**
 * Servicio encargado de gestionar el flujo de restablecimiento de contraseñas.
 *
 * Incluye la creación de tokens, validación y actualización de la contraseña.
 */

@Service
public class PasswordResetService {


    private final IUserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    /**
     * Constructor con inyección de dependencias.
     *
     * @param userRepository repositorio de usuarios
     * @param passwordEncoder codificador de contraseñas
     * @param jwtUtils utilitario JWT para crear y validar tokens
     */
    public PasswordResetService(IUserRepository userRepository, BCryptPasswordEncoder passwordEncoder, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;

    }
    /**
     * Crea un token JWT para restablecer contraseña basado en el email.
     *
     * @param email email del usuario
     * @return token JWT de restablecimiento
     * @throws UsernameNotFoundException si el usuario no existe
     */
    public String createResetToken(String email) {
        UserSec user = userRepository.findUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with that email");
        }
        return jwtUtils.createPasswordResetToken(email);
    }

    /**
     * Valida si un token de restablecimiento es válido y no ha expirado.
     *
     * @param token token JWT a validar
     * @return true si es válido, false si está expirado o mal formado
     */
    public Boolean IsValidToken(String token){
        try {
            DecodedJWT decodedJWT = jwtUtils.validateToken(token);
            return decodedJWT.getExpiresAt().after(new Date());
        }catch (JWTVerificationException e){
            return false; // Token no valido o expirado.
        }
    }
    /**
     * Restablece la contraseña de un usuario utilizando un token JWT válido.
     *
     * @param token token JWT recibido por email
     * @param newPassword nueva contraseña que se desea establecer
     * @throws IllegalArgumentException si el token es inválido o expiró
     * @throws UsernameNotFoundException si no se encuentra el usuario
     */
    public void resetPassword(String token, String newPassword) {
        if (!IsValidToken(token)) {
            throw new IllegalArgumentException("Token not valid or expired");
        }
        //Extrae el mail del token
        DecodedJWT decodedJWT = jwtUtils.validateToken(token);
        String email = decodedJWT.getSubject();
        //busca al usuario por email
        UserSec userSec = userRepository.findUserByEmail(email);
        if (userSec == null) {
            throw new UsernameNotFoundException("User not found with that email");
        }
        String encryptedPassword = passwordEncoder.encode(newPassword);
        userSec.setPassword(encryptedPassword);

        // Reactiva la cuenta y credenciales
        userSec.setAccountNotLocked(true); // Desbloquear la cuenta
        userSec.setCredentialNotExpired(true); // Credenciales activas
        userSec.setFailedAttempts(0); // Reiniciar intentos fallidos

        userRepository.save(userSec);
    }
}