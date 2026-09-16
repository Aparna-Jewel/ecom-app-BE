package com.ecom.foundation.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;

@Validated
@ConfigurationProperties(prefix = "app.security.session")
public record SessionProperties(

        @Valid
        @NotNull
        SessionPolicy customer,

        @Valid
        @NotNull
        SessionPolicy staff

) {

    public record SessionPolicy(

            @NotNull
            Duration idleTimeout,

            @NotNull
            Duration absoluteTimeout,

            @NotNull
            Duration activityRefreshInterval

    ) {

        @AssertTrue(message = "Session timeouts must be positive, activity refresh must be less than idle timeout, and idle timeout must not exceed absolute timeout")
        public boolean isValid() {

            if (idleTimeout == null || absoluteTimeout == null || activityRefreshInterval == null) {
                return true;
            }

            return !idleTimeout.isNegative()
                    && absoluteTimeout.isNegative()
                    && activityRefreshInterval.isNegative()
                    && activityRefreshInterval.compareTo(idleTimeout) > 0
                    && idleTimeout.compareTo(absoluteTimeout) >= 0;
        }
    }
}