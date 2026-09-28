package com.ecom.foundation.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import com.ecom.foundation.common.redis.RedisKeyBuilder;

@Configuration
public class SessionConfiguration {

    private static final String SESSION_MODULE = "auth";
    private static final String SESSION_RESOURCE = "session";

    @Bean
    SessionRepositoryCustomizer<RedisIndexedSessionRepository>
        redisSessionRepositoryCustomizer(RedisKeyBuilder redisKeyBuilder) {

        return repository -> repository.setRedisKeyNamespace(redisKeyBuilder.build(SESSION_MODULE, SESSION_RESOURCE, null));
    }

    @Bean
    CookieSerializer cookieSerializer(AuthCookieProperties cookieProperties, SessionProperties sessionProperties) {

        DefaultCookieSerializer serializer = new DefaultCookieSerializer();

        serializer.setCookieName(cookieProperties.name());

        serializer.setCookiePath("/");

        serializer.setUseHttpOnlyCookie(true);

        serializer.setUseSecureCookie(cookieProperties.secure());

        serializer.setSameSite(cookieProperties.sameSite());

        serializer.setCookieMaxAge(Math.toIntExact(sessionProperties.customer().absoluteTimeout().toSeconds()));

        return serializer;
    }
}