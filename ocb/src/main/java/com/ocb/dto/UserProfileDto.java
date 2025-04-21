package com.ocb.dto;

import lombok.Data;

@Data
public class UserProfileDto {
    private Long id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
}