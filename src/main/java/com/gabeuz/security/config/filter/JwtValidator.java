package com.gabeuz.security.config.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.gabeuz.security.service.UserDetailsServiceImpl;
import com.gabeuz.security.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
/**
 * Filtro personalizado para validar JWT en cada solicitud HTTP.
 * Se ejecuta una sola vez por request (gracias a OncePerRequestFilter).
 * Extrae el token del encabezado Authorization, lo valida y establece la autenticación en el contexto de seguridad.
 */
@Component
public class JwtValidator extends OncePerRequestFilter {
    @Autowired
    private  JwtUtils jwtUtils;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    public JwtValidator(JwtUtils jwtUtils){this.jwtUtils = jwtUtils;}

    /**
     * Método que intercepta todas las peticiones entrantes.
     * Si hay un JWT válido en el header Authorization, se autentica al usuario en el contexto de Spring Security.
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // Extrae el token del header "Authorization"
        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (jwtToken != null && jwtToken.startsWith("Bearer ")) {
            jwtToken = jwtToken.substring(7);// Elimina el prefijo "Bearer "

            try {
                // Valida el token y obtiene los datos decodificados
                DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken);

                if (decodedJWT != null) {
                    // Extrae el email (subject) y los roles del token
                    String email = jwtUtils.extractUsername(decodedJWT);
                    String authoritiesClaim = jwtUtils.getSpecificClaim(decodedJWT, "authorities").asString();

                    // Convierte el string de roles separados por coma a una lista de authorities
                    Collection<? extends GrantedAuthority> authoritiesList =
                            authoritiesClaim != null ? AuthorityUtils.commaSeparatedStringToAuthorityList(authoritiesClaim)
                                    : Collections.emptyList();

                    // Crea una autenticación basada en los datos extraídos del token
                    Authentication authentication = new UsernamePasswordAuthenticationToken(email, null, authoritiesList);

                    // Establece la autenticación en el contexto de seguridad
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e){
                // Bloquea la solicitud si el token es inválido
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\": \"Token inválido o expirado\"}");
                return;
            }

        }
        // Continúa con el resto de la cadena de filtros
        filterChain.doFilter(request, response);
    }
}
