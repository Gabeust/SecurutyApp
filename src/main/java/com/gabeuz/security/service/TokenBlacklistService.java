package com.gabeuz.security.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;
/**
 * Servicio encargado de gestionar una blacklist de tokens JWT usando Redis.
 *
 * Permite invalidar tokens manualmente (por ejemplo al cerrar sesión)
 * y verificar si un token fue previamente invalidado.
 */
@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;
    private static final String BLACKLIST_PREFIX = "blacklist:";
    /**
     * Constructor que recibe una instancia de RedisTemplate para manejar almacenamiento en Redis.
     *
     * @param redisTemplate plantilla de operaciones Redis para almacenar tokens bloqueados
     */
    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    /**
     * Agrega un token a la blacklist, almacenándolo en Redis con una expiración.
     *
     * @param token        el token JWT que se desea invalidar
     * @param expirationMs tiempo en milisegundos que el token permanecerá bloqueado (normalmente igual a su tiempo de expiración)
     */
    public void blacklistToken(String token, long expirationMs) {
        redisTemplate.opsForValue().set(BLACKLIST_PREFIX + token, "blacklisted", expirationMs, TimeUnit.MILLISECONDS);
    }
    /**
     * Verifica si un token está presente en la blacklist.
     *
     * @param token el token JWT a verificar
     * @return true si el token está en la blacklist, false en caso contrario
     */
    public boolean isTokenBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(BLACKLIST_PREFIX + token));
    }
}

