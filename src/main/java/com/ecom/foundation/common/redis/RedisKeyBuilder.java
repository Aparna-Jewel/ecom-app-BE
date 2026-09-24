package com.ecom.foundation.common.redis;

import static com.ecom.foundation.common.redis.RedisValidation.validateAndNormaliseString;
import static com.ecom.foundation.common.redis.RedisValidation.validateAndNormaliseIdentifierToken;

import org.springframework.stereotype.Component;

@Component
public class RedisKeyBuilder {
    private final RedisKeyProperties properties;

    public RedisKeyBuilder(RedisKeyProperties properties) {
        this.properties = properties;
    }

    public String build(
        String module,
        String resource,
        String identifierToken
    ) {
        StringBuilder key = new StringBuilder()
                            .append(properties.namespace())
                            .append(":")
                            .append(properties.environment());
        appendIfPresent(key, module);
        appendIfPresent(key, resource);
        appendIfPresent(key, identifierToken);
    
        return key.toString();
    }

    public static void appendIfPresent(StringBuilder key, String value) {
        if(value != null) {
            key.append(":").append(value);
        }
    }
}