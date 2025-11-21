package com.ryu.security.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

public class CustomUserDetails implements UserDetails {

    private final UserEntity user;

    public CustomUserDetails(UserEntity user) {
        this.user = user;
    }

    public Long getId() {
        return user.getId();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    /**
     * ROLE(USER/ADMIN) 꺼내기 위한 메서드 추가 (핵심)
     */
    public String getRole() {
        return user.getRole();    // "ROLE_USER" or "ROLE_ADMIN"
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 기존 방식도 동작은 하지만 권장 방식은 아님
        return List.of((GrantedAuthority) () -> user.getRole());
    }

    // equals / hashCode 구현
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CustomUserDetails other)) return false;
        return Objects.equals(this.getUsername(), other.getUsername());
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getUsername());
    }
}
