package com.gabeuz.security.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class UserSec {
     @Id
     @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
     @NotBlank
     @Column(unique = true)
     @Email
    private String email;
     @NotBlank
    private String password;
    private Boolean enable = true;
    private Boolean accountNotExpired = true;
    private Boolean accountNotLocked=true;
    private Boolean credentialNotExpired = true;
    private int failedAttempts = 0;
    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    private Set<Role> rolesList = new HashSet<>();
}
