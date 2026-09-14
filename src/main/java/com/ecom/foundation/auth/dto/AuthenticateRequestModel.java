package com.ecom.foundation.auth.dto;

import java.util.UUID;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record AuthenticateRequestModel(

    @NotBlank 
    String isd,
    
    @NotBlank 
    String mobile,
    
    String email,
 
    String name,

    String lastName,

    @NotBlank 
    String token,

    UUID termId

) {}
