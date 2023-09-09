package com.example.demo.security;

import static com.example.demo.security.Permission.*;

import java.util.Collections;
import java.util.Set;

public enum Role {
    STUDENT(
        Collections.emptySet()
    ),
    ADMIN(
        Set.of(
            COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WRITE
        )
    );

    private final Set<Permission> permissions;

    private Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }
}
