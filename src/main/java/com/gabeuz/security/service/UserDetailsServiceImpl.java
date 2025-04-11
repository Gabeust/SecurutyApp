package com.gabeuz.security.service;

import com.gabeuz.security.dto.AuthLoginRequestDTO;
import com.gabeuz.security.dto.AuthResponseDTO;
import com.gabeuz.security.model.UserSec;
import com.gabeuz.security.repository.IUserRepository;
import com.gabeuz.security.util.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
/**
 * Servicio que implementa {@link UserDetailsService} para cargar usuarios desde la base de datos
 * y realizar autenticaciones personalizadas.
 *
 * También maneja lógica de intentos fallidos, bloqueo de cuentas y generación de JWT al iniciar sesión.
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private IUserRepository userRepository;
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Carga un usuario por su email y construye el objeto {@link UserDetails} necesario para Spring Security.
     *
     * @param email correo electrónico del usuario
     * @return objeto {@link UserDetails} con roles y estado de la cuenta
     * @throws UsernameNotFoundException si no se encuentra el usuario
     * @throws LockedException si la cuenta está bloqueada
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserSec userSec = userRepository.findUserByEmail(email);
        if (userSec == null){
            throw new UsernameNotFoundException("User with email " + email + " was not found.");
        }
        if (!userSec.getAccountNotLocked()) {
            throw new LockedException("The account is locked due to multiple failed login attempts.");
        }
        //crea una lista para los permisos
        List<SimpleGrantedAuthority> authorityList = userSec.getRolesList().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .toList();

        return new User(userSec.getEmail(),
                userSec.getPassword(),
                userSec.getEnable(),
                userSec.getAccountNotExpired(),
                userSec.getAccountNotLocked(),
                userSec.getCredentialNotExpired(),
                authorityList);
    }
    /**
     * Realiza la autenticación de un usuario verificando su contraseña.
     * También maneja intentos fallidos y bloqueo de cuentas.
     *
     * @param email    correo del usuario
     * @param password contraseña sin encriptar
     * @return token de autenticación de Spring Security
     */
    public Authentication authenticate(String email, String password) {
        UserSec userSec = userRepository.findUserByEmail(email);

        if (userSec == null) {
            throw new UsernameNotFoundException("User not found.");
        }

        if (!userSec.getAccountNotLocked()) {
            throw new LockedException("Account locked due to multiple failed login attempts.");
        }

        if (!passwordEncoder.matches(password, userSec.getPassword())) {
            handleFailedLogin(userSec);
            throw new RuntimeException("Incorrect credentials.");
        }

        resetFailedAttempts(userSec);

        UserDetails userDetails = this.loadUserByUsername(email);
        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
    }
    /**
     * Inicia sesión del usuario, genera un JWT y lo retorna junto con el estado de autenticación.
     *
     * @param authLoginRequest objeto con email y password
     * @return DTO con email, mensaje, JWT y estado
     */
    public AuthResponseDTO loginUser(AuthLoginRequestDTO authLoginRequest){

        String email = authLoginRequest.email();
        String password = authLoginRequest.password();
        Authentication authentication = this.authenticate(email, password);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String accessToken = jwtUtils.createToken(authentication);
        return new AuthResponseDTO(email, "Login seccesfull", accessToken, true);
    }
    /**
     * Maneja un intento de login fallido, aumentando el contador y bloqueando la cuenta si supera el límite.
     *
     * @param userSec usuario a actualizar
     */
    private void handleFailedLogin(UserSec userSec) {
        int attempts = userSec.getFailedAttempts() + 1;
        userSec.setFailedAttempts(attempts);

        if (attempts >= 3) {
            userSec.setAccountNotLocked(false);// Bloquea la cuenta
            userSec.setCredentialNotExpired(false);
            userRepository.save(userSec);
            throw new LockedException("Account locked due to multiple failed login attempts.");
        }

        userRepository.save(userSec);
    }
    /**
     * Reinicia el contador de intentos fallidos si el login es exitoso.
     *
     * @param userSec usuario autenticado
     */
    private void resetFailedAttempts(UserSec userSec) {
        if (userSec.getFailedAttempts() > 0) {
            userSec.setFailedAttempts(0);
            userRepository.save(userSec);
        }
    }
}