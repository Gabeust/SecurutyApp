    package com.gabeuz.security.util;

    import com.auth0.jwt.JWT;
    import com.auth0.jwt.JWTVerifier;
    import com.auth0.jwt.algorithms.Algorithm;
    import com.auth0.jwt.exceptions.JWTVerificationException;
    import com.auth0.jwt.interfaces.Claim;
    import com.auth0.jwt.interfaces.DecodedJWT;
    import com.gabeuz.security.service.TokenBlacklistService;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.stereotype.Component;

    import java.util.Date;
    import java.util.Map;
    import java.util.UUID;
    import java.util.stream.Collectors;
    /**
     * Utilidad para la generación, validación e invalidación de tokens JWT.
     *
     * Esta clase permite crear tokens de acceso con claims personalizados, validar su integridad
     * y caducidad, así como invalidarlos utilizando una blacklist basada en Redis.
     */
    @Component
    public class JwtUtils {

        @Value("${spring.security.jwt.private.key}")
        private String privateKey;
        private final TokenBlacklistService tokenBlacklistService;
        /**
         * Constructor con inyección del servicio de blacklist.
         *
         * @param tokenBlacklistService servicio para gestionar tokens revocados
         */

        public JwtUtils(TokenBlacklistService tokenBlacklistService) {
            this.tokenBlacklistService = tokenBlacklistService;
        }
        /**
         * Genera un JWT para un usuario autenticado.
         *
         * @param authentication objeto de autenticación del usuario
         * @return token firmado con claims personalizados
         */
        public String createToken(Authentication authentication){
            Algorithm algorithm = Algorithm.HMAC256(privateKey);

            String email = authentication.getName();

            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority
            ).collect(Collectors.joining(","));

            return JWT.create().withSubject(email)
                    .withClaim("authorities", authorities).withIssuedAt(new Date())
                    .withExpiresAt(new Date(System.currentTimeMillis() + 18000000)).withJWTId(UUID.randomUUID().toString())
                    .withNotBefore(new Date(System.currentTimeMillis())).sign(algorithm);
        }

        /**
         * Genera un JWT para restablecimiento de contraseña con validez de 15 minutos.
         *
         * @param email email del usuario que solicita restablecer la contraseña
         * @return token temporal de recuperación
         */
        public String createPasswordResetToken(String email){
            Algorithm algorithm = Algorithm.HMAC256(privateKey);

               return JWT.create()
                        .withSubject(email)
                        .withIssuedAt(new Date())
                        .withExpiresAt(new Date(System.currentTimeMillis() + 900000)) // expira en 15 minutos
                        .withJWTId(UUID.randomUUID().toString())
                        .withNotBefore(new Date(System.currentTimeMillis()))
                        .sign(algorithm);
        }

        /**
         * Valida un token JWT, comprobando su firma, expiración y si fue revocado.
         *
         * @param token el JWT recibido del cliente
         * @return objeto {@link DecodedJWT} si el token es válido
         * @throws JWTVerificationException si el token es inválido, expirado o está en la blacklist
         */
        public DecodedJWT validateToken(String token) {
            //  Si el token está en Redis, significa que fue revocado
            if (tokenBlacklistService.isTokenBlacklisted(token)) {
                throw new JWTVerificationException("Token inválido o expirado");
            }

            try {
                Algorithm algorithm = Algorithm.HMAC256(privateKey);
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(token);

                // Verificar manualmente si el token ha expirado
                if (decodedJWT.getExpiresAt().before(new Date())) {
                    throw new JWTVerificationException("Token expirado");
                }

                return decodedJWT;
            } catch (JWTVerificationException e) {
                throw new JWTVerificationException("Token inválido, no autorizado");
            }
        }
        /**
         * Invalida un token JWT añadiéndolo a Redis con su tiempo restante de vida.
         *
         * @param token el JWT a invalidar
         */
        public void invalidateToken(String token) {
            DecodedJWT decodedJWT = JWT.decode(token);
            long expiresIn = decodedJWT.getExpiresAt().getTime() - System.currentTimeMillis();
            tokenBlacklistService.blacklistToken(token, expiresIn);
        }

        /**
         * Extrae el email (subject) de un JWT ya validado.
         *
         * @param decodedJWT JWT decodificado
         * @return el subject del token (email del usuario)
         */

        public String extractUsername(DecodedJWT decodedJWT){
            return decodedJWT.getSubject();
        }

        /**
         * Obtiene un claim específico del JWT.
         *
         * @param decodedJWT token decodificado
         * @param claimName nombre del claim
         * @return el claim solicitado
         */
        public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName){
            return decodedJWT.getClaim(claimName);
        }
        /**
         * Retorna todos los claims del token.
         *
         * @param decodedJWT token decodificado
         * @return mapa de claims
         */
        public Map<String, Claim> returnAllClaim(DecodedJWT decodedJWT){
            return decodedJWT.getClaims();
        }

    }
