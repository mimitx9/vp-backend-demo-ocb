package com.ocb.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private boolean authenticated;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Integer passwordAgeDays;
    private String message;
    private String errorCode;
}